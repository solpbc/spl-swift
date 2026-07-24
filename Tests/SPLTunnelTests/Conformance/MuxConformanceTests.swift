// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("MuxConformance")
struct MuxConformanceTests {
    @Test func dialerAdmitsValidEvenInboundOpen() async throws {
        // proto/framing.md:104,108 reserves listener-opened even ids; only wrong-parity OPEN draws RESET.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let incoming = Task { try await firstIncomingStream(from: mux.incomingStreams) }

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 2)))

        let stream = try await incoming.value
        #expect(stream.id == 2)
        #expect(await recorder.frames().isEmpty)
    }

    @Test func windowOnStreamZeroIsTunnelFatal() async throws {
        // proto/framing.md:105,179: WINDOW on stream 0 is reserved and currently a protocol error.
        let mux = Multiplexer(sink: { _ in }, role: .dialer)

        await expectFramingError(.unknownControlFrame) {
            try await mux.feedInbound(try encodeFrame(buildWindow(streamID: 0, credit: 1)))
        }
    }

    @Test func openOnStreamZeroIsTunnelFatal() async throws {
        // proto/framing.md:105,179: only PING/PONG are valid on stream 0 in v1.
        let mux = Multiplexer(sink: { _ in }, role: .dialer)

        await expectFramingError(.unknownControlFrame) {
            try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 0)))
        }
    }

    @Test func dataCloseResetOnStreamZeroAreTunnelFatal() async throws {
        // proto/framing.md:105 DATA, CLOSE, and RESET on stream 0 are tunnel-fatal protocol errors.
        let cases: [(flags: UInt8, payload: Data)] = [
            (FrameFlags.data.rawValue, Data([0x41])),
            (FrameFlags.close.rawValue, Data()),
            (FrameFlags.reset.rawValue, Data([ResetReason.cancel.rawValue])),
        ]

        for testCase in cases {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

            await expectFramingError(.unknownControlFrame) {
                try await mux.feedInbound(rawMuxFrame(
                    streamID: 0,
                    flags: testCase.flags,
                    payload: testCase.payload
                ))
            }

            #expect(await recorder.frames().isEmpty)
        }
    }

    @Test func malformedStreamZeroControlFrameIsTunnelFatal() async {
        // proto/framing.md:60 permits OPEN|DATA as a stream frame, not as a stream-zero control frame.
        let mux = Multiplexer(sink: { _ in }, role: .dialer)
        let malformed = rawMuxFrame(
            streamID: 0,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: Data([0x41])
        )

        await expectFramingError(.unknownControlFrame) {
            try await mux.feedInbound(malformed)
        }
    }

    @Test func unknownStreamDataDrawsOneProtocolReset() async throws {
        // proto/framing.md:110-112 says DATA for an unknown id asserts liveness and draws one RESET.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        try await mux.feedInbound(try encodeFrame(buildData(streamID: 9, payload: Data([0x41]))))

        let reset = try #require(await recorder.frames().last)
        #expect(reset.streamID == 9)
        #expect(reset.flags == FrameFlags.reset.rawValue)
        #expect(parseResetReason(from: reset.payload).reason == .protocolError)
    }

    @Test func unknownStreamCloseAndResetAreSilentlyTolerated() async throws {
        // proto/framing.md:110-112 says CLOSE/RESET for an unknown id may race teardown and are tolerated.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        try await mux.feedInbound(try encodedMuxFrames(
            buildClose(streamID: 9),
            buildReset(streamID: 11, reason: .cancel)
        ))

        #expect(await recorder.frames().isEmpty)
    }

    @Test func strayPongIsSilentlyDropped() async throws {
        // proto/framing.md:146-159 unsolicited PONG frames are tolerated and silently dropped.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        try await mux.feedInbound(try encodeFrame(buildPong(nonce: Data([1, 2, 3, 4, 5, 6, 7, 8]))))
        #expect(await recorder.frames().isEmpty)

        _ = try await mux.openStream()
        let open = try #require(await recorder.frames().last)
        #expect(open.streamID == 1)
        #expect(open.flags == FrameFlags.open.rawValue)
    }

    @Test func initialCreditIsOneMiB() {
        // proto/framing.md:124 each side starts with 1 MiB of send credit when a stream opens.
        #expect(MuxConstants.initialCredit == 1 << 20)
    }

    @Test func dataQueuedAndUndrainedDoesNotEmitWindowGrant() async throws {
        // proto/framing.md:124-129 returns credit as the application drains, not when mux queues bytes.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()
        let payload = Data(repeating: 0x31, count: MuxConstants.windowGrantThreshold)

        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: payload)))

        #expect(await stream.queuedInboundByteCount() == payload.count)
        #expect(await mux.queuedInboundByteCount() == payload.count)
        #expect(await recorder.frames().isEmpty)
    }

    @Test func windowGrantSinkFailureSurfacesFromInboundIteratorNext() async throws {
        // proto/framing.md:124-129 moves WINDOW writes onto the consumer drain path.
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.window.rawValue))
        let mux = Multiplexer(sink: { bytes in try await sink.recordOrThrow(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        let payload = Data(repeating: 0x32, count: MuxConstants.windowGrantThreshold)
        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: payload)))
        var iterator = stream.inbound.makeAsyncIterator()

        do {
            _ = try await iterator.next()
            Issue.record("Expected sink failure")
        } catch let error as MuxTestError {
            #expect(error == .sinkFailure)
        } catch {
            Issue.record("Expected sink failure, got \(error)")
        }
    }

    @Test func inboundIteratorRetainsStreamLongEnoughToReturnDrainCredit() async throws {
        // proto/framing.md:124-129: draining application bytes must return WINDOW even if only iteration remains.
        let recorder = MuxFrameRecorder()
        var stream: MuxStream? = MuxStream(
            id: 1,
            sink: { bytes in try await recorder.record(bytes) },
            onTerminal: { _ in }
        )
        let inbound = try #require(stream?.inbound)
        let payload = Data(repeating: 0x39, count: MuxConstants.windowGrantThreshold)
        #expect(await stream?.deliverInboundData(payload) == .accepted)
        stream = nil
        var iterator = inbound.makeAsyncIterator()

        #expect(try await iterator.next() == payload)
        let window = try #require(await recorder.frames().last)
        #expect(window.streamID == 1)
        #expect(window.flags == FrameFlags.window.rawValue)
        #expect(try parseWindowCredit(from: window.payload) == UInt32(payload.count))
    }

    @Test func listenerOpenDataFullInitialCreditDebitsWindowUntilConsumerDrains() async throws {
        // proto/framing.md:60,124-129: OPEN initial payload counts against receive credit until drained.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = Task { try await firstIncomingStream(from: mux.incomingStreams) }
        let payload = Data(repeating: 0x33, count: Int(MuxConstants.initialCredit))
        let openData = Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: payload
        )

        try await mux.feedInbound(try encodeFrame(openData))
        let stream = try await incoming.value

        #expect(await stream.queuedInboundByteCount() == payload.count)
        #expect(await recorder.frames().isEmpty)

        var iterator = stream.inbound.makeAsyncIterator()
        let received = try await iterator.next()
        #expect(received?.count == payload.count)
        let window = try #require(await recorder.frames().last)
        #expect(window.streamID == 1)
        #expect(window.flags == FrameFlags.window.rawValue)
        #expect(try parseWindowCredit(from: window.payload) == MuxConstants.initialCredit)
    }

    @Test func composedOpenDataDeliversInitialPayloadWithoutWindowGrant() async throws {
        // proto/framing.md:60,124-129: OPEN|DATA queues initial bytes but credit returns only on drain.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = Task { try await firstIncomingStream(from: mux.incomingStreams) }
        let payload = Data([0x41, 0x42])

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: payload
        )))

        let stream = try await incoming.value
        #expect(try await readInboundPayload(from: stream) == payload)
        #expect(await recorder.frames().isEmpty)
    }

    @Test func listenerOpenDataCloseDeliversPayloadThenEofNoWindowGrant() async throws {
        // proto/framing.md:110-112: once the peer finished the stream, do not WINDOW an id it may forget.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = Task { try await firstIncomingStream(from: mux.incomingStreams) }
        let payload = Data(repeating: 0x34, count: MuxConstants.windowGrantThreshold)
        let openDataClose = Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue | FrameFlags.close.rawValue,
            payload: payload
        )

        try await mux.feedInbound(try encodeFrame(openDataClose))
        let stream = try await incoming.value
        var iterator = stream.inbound.makeAsyncIterator()

        #expect(try await iterator.next() == payload)
        #expect(try await iterator.next() == nil)
        #expect(await recorder.frames().isEmpty)
    }

    @Test func singleStreamQueuedInboundBytesNeverExceedReceiveWindow() async throws {
        // proto/framing.md:124-129 bounds queued-but-undrained bytes by the per-stream receive window.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildData(
            streamID: stream.id,
            payload: Data(repeating: 0x35, count: Int(MuxConstants.initialCredit))
        )))

        #expect(await stream.queuedInboundByteCount() == Int(MuxConstants.initialCredit))
        #expect(await stream.queuedInboundByteCount() <= Int(MuxConstants.initialCredit))
        #expect(await recorder.frames().isEmpty)

        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x00]))))
        let reset = try #require(await recorder.frames().last)
        #expect(reset.flags == FrameFlags.reset.rawValue)
        #expect(parseResetReason(from: reset.payload).reason == .flowControlError)
        #expect(await stream.queuedInboundByteCount() <= Int(MuxConstants.initialCredit))
    }

    @Test func overWindowDataIsolatesKnownStreamOnceAndIgnoresLateReset() async throws {
        // proto/framing.md:124-129,215: over-window DATA resets the stream; late RESET is tolerated.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildData(
            streamID: stream.id,
            payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
        )))
        try await mux.feedInbound(try encodeFrame(buildReset(streamID: stream.id, reason: .cancel)))

        try await expectResetFrames(in: recorder, streamID: stream.id, reason: .flowControlError, count: 1)
        #expect(await stream.state == .resetLocal)
    }

    @Test func concurrentStreamsEachStayWithinReceiveWindow() async throws {
        // proto/framing.md:118,124-129: the stream cap and per-stream credit bound concurrent queues.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        var incoming = mux.incomingStreams.makeAsyncIterator()

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let first = try #require(await incoming.next())
        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 3)))
        let second = try #require(await incoming.next())

        let fullWindow = Data(repeating: 0x36, count: Int(MuxConstants.initialCredit))
        try await mux.feedInbound(try encodedMuxFrames(
            buildData(streamID: first.id, payload: fullWindow),
            buildData(streamID: second.id, payload: fullWindow)
        ))

        #expect(await first.queuedInboundByteCount() <= Int(MuxConstants.initialCredit))
        #expect(await second.queuedInboundByteCount() <= Int(MuxConstants.initialCredit))
        #expect(await mux.queuedInboundByteCount() == Int(MuxConstants.initialCredit) * 2)
    }

    @Test func senderCannotExceedRemainingCredit() async throws {
        // proto/framing.md:124-127: a sender with zero credit MUST NOT send DATA.
        let recorder = MuxFrameRecorder()
        let stream = MuxStream(id: 1, sink: { bytes in try await recorder.record(bytes) }, onTerminal: { _ in })
        try await stream.write(Data(repeating: 0x37, count: Int(MuxConstants.initialCredit)))
        let framesBeforeBlockedWrite = await recorder.count()
        let writer = Task { try await stream.write(Data([0x38])) }

        let emittedWithoutCredit = await conditionObserved {
            await recorder.count() > framesBeforeBlockedWrite
        }
        #expect(emittedWithoutCredit == false)
        #expect(await recorder.count() == framesBeforeBlockedWrite)

        #expect(await stream.grantSendCredit(1) == .accepted)
        try await writer.value
        #expect(await recorder.count() == framesBeforeBlockedWrite + 1)
    }

    @Test func sendCreditCapAcceptsInt32MaxAndRejectsOverflowWithoutMutation() async throws {
        // proto/framing.md:126: remaining send credit above 2^31-1 is a FLOW_CONTROL_ERROR.
        let recorder = MuxFrameRecorder()
        let stream = MuxStream(id: 1, sink: { bytes in try await recorder.record(bytes) }, onTerminal: { _ in })
        let roomToMax = UInt32(Int32.max) - MuxConstants.initialCredit

        #expect(await stream.grantSendCredit(roomToMax) == .accepted)
        #expect(await stream.grantSendCredit(1) == .flowControlExceeded)
        try await stream.write(Data([0x41]))
        #expect(await stream.grantSendCredit(1) == .accepted)
        #expect(await stream.grantSendCredit(1) == .flowControlExceeded)
    }

    @Test func sendCreditCapThroughDispatchIsolatesOverflowOnce() async throws {
        // proto/framing.md:126,215: over-crediting a live stream resets only the offending stream.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()
        let largeCredit = UInt32(1 << 30)

        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: largeCredit)))
        #expect(await resetCount(in: recorder, streamID: stream.id, reason: .flowControlError) == 0)
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: largeCredit)))
        #expect(await resetCount(in: recorder, streamID: stream.id, reason: .flowControlError) == 1)

        _ = try await mux.openStream()
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: 3, credit: UInt32.max)))
        #expect(await resetCount(in: recorder, streamID: 3, reason: .flowControlError) == 1)

        let boundary = try await mux.openStream()
        let grantToBoundary = UInt32(Int(Int32.max) - Int(MuxConstants.initialCredit))
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: boundary.id, credit: grantToBoundary)))
        #expect(await resetCount(in: recorder, streamID: boundary.id, reason: .flowControlError) == 0)
        try await boundary.write(Data([0x41]))
        #expect(await recorder.frames().contains {
            $0.streamID == boundary.id && $0.flags == FrameFlags.data.rawValue && $0.payload == Data([0x41])
        })
    }

    @Test func streamZeroPingWindowCombinationIsFatalWithoutPong() async throws {
        // proto/framing.md:105,179: stream-zero WINDOW is reserved; only singleton PING/PONG are valid.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        await expectFramingError(.unknownControlFrame) {
            try await mux.feedInbound(rawMuxFrame(
                streamID: 0,
                flags: FrameFlags.ping.rawValue | FrameFlags.window.rawValue,
                payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
            ))
        }

        #expect(await recorder.frames().isEmpty)
    }

    @Test func duplicateInboundOpenResetsWithoutClobberingLiveStream() async throws {
        // proto/framing.md:101-108,215: duplicate OPEN is a stream protocol violation.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams
        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let stream = try await firstIncomingStream(from: incoming)
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
        await recorder.reset()
        try await stream.write(Data([0xa5]))
        let data = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(data.streamID == 1)
    }

    @Test func inboundOpenInitialPayloadOverWindowResetsBeforeYield() async throws {
        // proto/framing.md:60,124-129: initial OPEN bytes debit receive credit before delivery.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
        )))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .flowControlError)
        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x01]))))
        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
    }

    private func resetCount(
        in recorder: MuxFrameRecorder,
        streamID: UInt32,
        reason: ResetReason
    ) async -> Int {
        await recorder.frames().filter {
            $0.streamID == streamID &&
                $0.flags == FrameFlags.reset.rawValue &&
                parseResetReason(from: $0.payload).reason == reason
        }.count
    }
}
