// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("Multiplexer")
struct MultiplexerTests {
    @Test func outboundIDsAllocateOddMonotonically() async throws {
        // proto/framing.md:101-106 dialing side uses odd stream ids monotonically.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        _ = try await mux.openStream()
        _ = try await mux.openStream()
        _ = try await mux.openStream()

        #expect(await recorder.frames().map(\.streamID) == [1, 3, 5])
    }

    @Test func listenerOutboundIDsAllocateEvenMonotonically() async throws {
        // proto/framing.md:101-106 listening side uses even stream ids monotonically.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)

        _ = try await mux.openStream()
        _ = try await mux.openStream()
        _ = try await mux.openStream()

        #expect(await recorder.frames().map(\.streamID) == [2, 4, 6])
    }

    @Test func dialerInboundOddOpenEmitsProtocolReset() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))

        let reset = try #require(await recorder.frames().last)
        #expect(reset.streamID == 1)
        #expect(reset.flags == FrameFlags.reset.rawValue)
        #expect(parseResetReason(from: reset.payload).reason == .protocolError)
    }

    @Test func listenerInboundOddOpenIsAcceptedAndYielded() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = Task { try await firstIncomingStream(from: mux.incomingStreams) }

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))

        let stream = try await incoming.value
        #expect(stream.id == 1)
        #expect(await recorder.frames().isEmpty)
    }

    @Test func listenerInboundEvenOpenEmitsProtocolReset() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 2)))

        let reset = try #require(await recorder.frames().last)
        #expect(reset.streamID == 2)
        #expect(reset.flags == FrameFlags.reset.rawValue)
        #expect(parseResetReason(from: reset.payload).reason == .protocolError)
    }

    @Test func openStreamDeliversInboundResetWhileOpenSendIsSuspended() async throws {
        let sink = BlockingFirstMuxSink()
        let mux = Multiplexer(sink: { bytes in try await sink.record(bytes) }, role: .dialer)
        let opener = Task { try await mux.openStream() }

        await sink.waitUntilEntered()
        try await mux.feedInbound(try encodeFrame(buildReset(streamID: 1, reason: .cancel)))
        await sink.release()

        let stream = try await opener.value
        #expect(await stream.state == .resetRemote)
        var iterator = stream.inbound.makeAsyncIterator()
        do {
            _ = try await iterator.next()
            Issue.record("Expected typed stream reset")
        } catch let error as MuxError {
            #expect(error == .streamReset(streamID: 1, reason: .cancel, rawByte: ResetReason.cancel.rawValue))
        } catch {
            Issue.record("Expected typed stream reset, got \(error)")
        }
    }

    @Test func openStreamSendFailureRollsBackRegisteredStreamOnly() async throws {
        let sink = SelectiveMuxSink(failureMode: .first)
        let failingMux = Multiplexer(sink: { bytes in try await sink.recordOrThrow(bytes) }, role: .dialer)
        do {
            _ = try await failingMux.openStream()
            Issue.record("Expected sink failure")
        } catch let error as MuxTestError {
            #expect(error == .sinkFailure)
        } catch {
            Issue.record("Expected sink failure, got \(error)")
        }

        try await failingMux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x01]))))
        let reset = try #require(await sink.frames().first)
        #expect(reset.streamID == 1)
        #expect(reset.flags == FrameFlags.reset.rawValue)
        #expect(parseResetReason(from: reset.payload).reason == .protocolError)
    }

    @Test func inboundResetSurfacesTypedStreamResetThroughInbound() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: stream.id,
            flags: FrameFlags.reset.rawValue,
            payload: Data([0x7e])
        )))

        var iterator = stream.inbound.makeAsyncIterator()
        do {
            _ = try await iterator.next()
            Issue.record("Expected typed stream reset")
        } catch let error as MuxError {
            #expect(error == .streamReset(streamID: stream.id, reason: .unspecified, rawByte: 0x7e))
        } catch {
            Issue.record("Expected typed stream reset, got \(error)")
        }
    }

    @Test func validInboundResetTerminatesOnlyTargetStreamSiblingSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let first = try await mux.openStream()
        let second = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildReset(streamID: first.id, reason: .cancel)))
        try await second.write(Data([0x41]))

        #expect(await first.state == .resetRemote)
        #expect(await second.state == .open)
        let data = try #require(await recorder.frames().last)
        #expect(data.streamID == second.id)
        #expect(data.flags == FrameFlags.data.rawValue)
    }

    @Test func longResetPayloadIsStreamScopedNotTunnelFatal() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: stream.id,
            flags: FrameFlags.reset.rawValue,
            payload: Data([ResetReason.cancel.rawValue, ResetReason.protocolError.rawValue])
        )))

        #expect(await stream.state == .resetRemote)
        #expect(await mux.inboundActivitySnapshot() == 1)
    }

    @Test func inboundCloseAfterLocalCloseRemovesTerminalStream() async throws {
        // proto/framing.md:75-98 a stream closes after both sides send CLOSE.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await stream.close()
        #expect(await stream.state == .halfClosedLocal)

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

        #expect(await stream.state == .closed)
        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
        try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
    }

    @Test func inboundCloseOnOpenStreamHalfClosesWithoutRemoving() async throws {
        // proto/framing.md:75-98 inbound CLOSE moves an open stream to remote-half-closed.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

        #expect(await stream.state == .halfClosedRemote)
        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
        await expectNoResetFrames(in: recorder)
    }

    @Test func localResetRemovesTerminalStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        await stream.reset(reason: .cancel)

        #expect(await stream.state == .resetLocal)
        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
        try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
    }

    @Test func activeStreamLimitCountsHalfClosedLocalStreams() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        var streams: [MuxStream] = []
        streams.reserveCapacity(MuxConstants.maxConcurrentStreams)
        for _ in 0..<MuxConstants.maxConcurrentStreams {
            streams.append(try await mux.openStream())
        }

        try await streams[0].close()
        await expectMuxError(.streamLimitExceeded) {
            try await mux.openStream()
        }

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: streams[0].id)))
        _ = try await mux.openStream()
    }

    @Test func activeStreamLimitStillCountsActiveStreamsOnlyAfterTerminalClose() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        var streams: [MuxStream] = []
        streams.reserveCapacity(MuxConstants.maxConcurrentStreams)
        for _ in 0..<MuxConstants.maxConcurrentStreams {
            streams.append(try await mux.openStream())
        }

        await expectMuxError(.streamLimitExceeded) {
            try await mux.openStream()
        }
        try await streams[0].close()
        await expectMuxError(.streamLimitExceeded) {
            try await mux.openStream()
        }

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: streams[0].id)))
        let next = try await mux.openStream()
        #expect(next.id == 513)
    }

    @Test func concurrentOpenStreamCallsCannotExceedCap() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        for _ in 0..<(MuxConstants.maxConcurrentStreams - 1) {
            _ = try await mux.openStream()
        }
        await recorder.reset()

        let attempts = 32
        let outcomes = await withTaskGroup(of: Bool?.self, returning: [Bool?].self) { group in
            for _ in 0..<attempts {
                group.addTask {
                    do {
                        _ = try await mux.openStream()
                        return true
                    } catch let error as MuxError where error == .streamLimitExceeded {
                        return false
                    } catch {
                        return nil
                    }
                }
            }

            var collected: [Bool?] = []
            for await outcome in group {
                collected.append(outcome)
            }
            return collected
        }

        #expect(outcomes.filter { $0 == true }.count == 1)
        #expect(outcomes.filter { $0 == false }.count == attempts - 1)
        #expect(outcomes.allSatisfy { $0 != nil })
        #expect(await recorder.frames().filter { $0.flags == FrameFlags.open.rawValue }.count == 1)
    }

    @Test func creditSuspendResume() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        let complete = AsyncResultBox<Bool>()
        let writer = Task {
            try await stream.write(Data(repeating: 0, count: 800 * 1024))
            try await stream.write(Data(repeating: 0, count: 300 * 1024))
            await complete.store(true)
        }

        let firstWriteFrames = ((800 * 1024) + MuxConstants.recommendedChunk - 1) / MuxConstants.recommendedChunk
        let framesBeforeSuspension = 1 + firstWriteFrames + 3
        await waitUntil("writer consumed available credit") {
            await recorder.count() == framesBeforeSuspension
        }
        #expect(await complete.snapshot() == nil)

        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 200 * 1024)))
        try await writer.value
        #expect(await complete.snapshot() == true)
    }

    @Test func writeChunksLargePayload() async throws {
        // proto/framing.md:189-197 large writes split into recommended 64 KiB DATA frames.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()

        try await stream.write(Data(repeating: 0, count: 200 * 1024))

        let frames = await recorder.frames()
        #expect(frames.count >= 3)
        #expect(frames.allSatisfy { $0.flags == FrameFlags.data.rawValue })
        #expect(frames.allSatisfy { $0.payload.count <= MuxConstants.recommendedChunk })
    }

    @Test func inboundDataEmitsWindowGrantAfterReaderDrains() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildData(
            streamID: stream.id,
            payload: Data(repeating: 0, count: 70 * 1024)
        )))

        #expect(try await readInboundPayload(from: stream)?.count == 70 * 1024)
        let window = try #require(await recorder.frames().first { $0.flags == FrameFlags.window.rawValue })
        #expect(window.streamID == stream.id)
        #expect(try parseWindowCredit(from: window.payload) == 70 * 1024)
    }

    @Test func halfCloseRoundTrip() async throws {
        // proto/framing.md:75-98 local and remote CLOSE complete the half-close lifecycle.
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await stream.close()
        try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

        #expect(await stream.state == .closed)
        #expect(try await inboundFinished(from: stream))
    }

    @Test func inboundResetThrowsAndBarsWrites() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await mux.feedInbound(try encodeFrame(buildReset(streamID: stream.id, reason: .protocolError)))

        var iterator = stream.inbound.makeAsyncIterator()
        await expectMuxError(.streamReset(
            streamID: stream.id,
            reason: .protocolError,
            rawByte: ResetReason.protocolError.rawValue
        )) {
            _ = try await iterator.next()
        }
        await expectMuxError(.writeAfterClose) {
            try await stream.write(Data([0x01]))
        }
    }

    @Test func inboundResetWithUnknownReasonDoesNotTearDownMux() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let first = try await mux.openStream()
        let sibling = try await mux.openStream()

        try await mux.feedInbound(rawMuxFrame(
            streamID: first.id,
            flags: FrameFlags.reset.rawValue,
            payload: Data([0x42])
        ))

        await recorder.reset()
        try await sibling.write(Data([0xa5]))
        let outboundData = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(outboundData.streamID == sibling.id)
        #expect(outboundData.payload == Data([0xa5]))

        try await mux.feedInbound(try encodeFrame(buildData(streamID: sibling.id, payload: Data([0x5a]))))
        #expect(try await readInboundPayload(from: sibling) == Data([0x5a]))

        let next = try await mux.openStream()
        #expect(next.id == 5)
    }

    @Test func terminalCloseEvictionLateDataResetsInBothCloseOrders() async throws {
        do {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
            let stream = try await mux.openStream()
            let sibling = try await mux.openStream()

            try await stream.close()
            try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

            await recorder.reset()
            try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
            try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
            try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
        }

        do {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
            let stream = try await mux.openStream()
            let sibling = try await mux.openStream()

            try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))
            try await stream.close()

            await recorder.reset()
            try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
            try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
            try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
        }
    }

    @Test func inboundResetEvictionAppliesWithinSameFeedInboundBuffer() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()
        await recorder.reset()
        var bytes = try encodeFrame(buildReset(streamID: stream.id, reason: .cancel))
        bytes.append(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x5a]))))

        try await mux.feedInbound(bytes)

        try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
    }

    @Test func terminalResetEvictionLateDataResetsForAllResetPaths() async throws {
        for scenario in 0..<3 {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
            let stream = try await mux.openStream()

            switch scenario {
            case 0:
                try await mux.feedInbound(try encodeFrame(buildReset(streamID: stream.id, reason: .cancel)))
            case 1:
                try await mux.feedInbound(try encodeFrame(Frame(
                    streamID: stream.id,
                    flags: FrameFlags.window.rawValue,
                    payload: Data([0x00, 0x00, 0x00])
                )))
            default:
                await stream.reset(reason: .cancel)
            }

            await recorder.reset()
            try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
            try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
        }
    }

    @Test func listenerAcceptsFreshOpenForPreviouslyPrunedID() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let first = try await firstIncomingStream(from: incoming)
        try await first.close()
        try await mux.feedInbound(try encodeFrame(buildClose(streamID: 1)))

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let second = try await firstIncomingStream(from: incoming)
        #expect(second.id == 1)
        await expectNoResetFrames(in: recorder)

        try await second.close()
        try await mux.feedInbound(try encodeFrame(buildClose(streamID: 1)))

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
            payload: Data()
        )))
        let third = try await firstIncomingStream(from: incoming)
        #expect(third.id == 1)
        #expect(try await inboundFinished(from: third))
        await expectNoResetFrames(in: recorder)

        await recorder.reset()
        try await third.write(Data([0xa5]))
        let outboundData = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(outboundData.streamID == 1)
        #expect(outboundData.payload == Data([0xa5]))
    }

    @Test func halfClosedLocalRetainedKeepsDeliveringInboundData() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await stream.close()

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x5a]))))

        #expect(try await readInboundPayload(from: stream) == Data([0x5a]))
        await expectNoResetFrames(in: recorder)
    }

    @Test func halfClosedRemoteRetainedKeepsWritingToSink() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let stream = try await mux.openStream()

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
        await expectNoResetFrames(in: recorder)

        await recorder.reset()
        try await stream.write(Data([0xa5]))

        let data = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(data.streamID == stream.id)
        #expect(data.payload == Data([0xa5]))
        await expectNoResetFrames(in: recorder)
    }

    @Test func streamTableStaysBoundedAcrossManyFullCloseCycles() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        for _ in 0..<100 {
            let stream = try await mux.openStream()
            try await stream.close()
            try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))

            await recorder.reset()
            try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: Data([0x01]))))
            try await expectResetFrame(in: recorder, streamID: stream.id, reason: .protocolError)
        }

        let next = try await mux.openStream()
        #expect(next.id == 201)
    }

    @Test func manyShortTerminalStreamsDoNotAccumulate() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        var closedIDs: [UInt32] = []

        for _ in 0..<100 {
            let stream = try await mux.openStream()
            closedIDs.append(stream.id)
            try await stream.close()
            try await mux.feedInbound(try encodeFrame(buildClose(streamID: stream.id)))
        }

        for streamID in [closedIDs.first, closedIDs.last].compactMap({ $0 }) {
            await recorder.reset()
            try await mux.feedInbound(try encodeFrame(buildData(streamID: streamID, payload: Data([0x01]))))
            try await expectResetFrame(in: recorder, streamID: streamID, reason: .protocolError)
        }
    }

    @Test func tearDownClearsAndFinishesRemainingLiveStreams() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let live = try await mux.openStream()
        let halfClosedLocal = try await mux.openStream()
        let liveSibling = try await mux.openStream()
        try await halfClosedLocal.close()

        await mux.tearDown(reason: .transportFailure)

        for stream in [live, halfClosedLocal, liveSibling] {
            #expect(await stream.state == .closed)
            var iterator = stream.inbound.makeAsyncIterator()
            await expectMuxError(.transportClosed) {
                _ = try await iterator.next()
            }
        }
        await expectMuxError(.transportClosed) {
            try await mux.openStream()
        }
    }

    @Test func malformedWindowResetsOnlyThatStreamAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: isolated.id,
            flags: FrameFlags.window.rawValue,
            payload: Data([0x00, 0x00, 0x00])
        )))

        try await assertIsolatedAndMuxSurvives(
            mux: mux,
            recorder: recorder,
            isolated: isolated,
            sibling: sibling,
            expectedReason: .protocolError
        )
    }

    @Test func repeatedMalformedWindowAfterPruneEmitsResetPerFrame() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: isolated.id,
            flags: FrameFlags.window.rawValue,
            payload: Data([0x00, 0x00, 0x00])
        )))
        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: isolated.id,
            flags: FrameFlags.window.rawValue,
            payload: Data([0x00, 0x00, 0x00, 0x00, 0x00])
        )))

        try await expectResetFrames(in: recorder, streamID: isolated.id, reason: .protocolError, count: 2)
        try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
        let next = try await mux.openStream()
        #expect(next.id == 5)
    }

    @Test func overWindowDataResetsOnlyThatStreamAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildData(
            streamID: isolated.id,
            payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
        )))

        try await assertIsolatedAndMuxSurvives(
            mux: mux,
            recorder: recorder,
            isolated: isolated,
            sibling: sibling,
            expectedReason: .flowControlError
        )
    }

    @Test func nonzeroPingAndPongResetOnlyThatStreamAndMuxSurvive() async throws {
        for flag in [FrameFlags.ping.rawValue, FrameFlags.pong.rawValue] {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
            let isolated = try await mux.openStream()
            let sibling = try await mux.openStream()
            await recorder.reset()

            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: isolated.id,
                flags: flag,
                payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
            )))

            try await assertIsolatedAndMuxSurvives(
                mux: mux,
                recorder: recorder,
                isolated: isolated,
                sibling: sibling,
                expectedReason: .protocolError
            )
        }
    }

    @Test func isolationResetSinkFailurePropagates() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.reset.rawValue))
        let mux = Multiplexer(sink: { bytes in try await sink.recordOrThrow(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()

        do {
            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: isolated.id,
                flags: FrameFlags.window.rawValue,
                payload: Data([0x00, 0x00, 0x00])
            )))
            Issue.record("Expected reset sink failure")
        } catch let error as MuxTestError {
            #expect(error == .sinkFailure)
        } catch {
            Issue.record("Expected reset sink failure, got \(error)")
        }

        #expect(await sink.matchingFrameCount(flags: FrameFlags.reset.rawValue) == 1)
        #expect(await isolated.state == .resetLocal)
    }

    @Test func windowCreditCapIsolatesOnlyOffendingStreamAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()
        let credit = UInt32(1 << 30)

        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: isolated.id, credit: credit)))
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: isolated.id, credit: credit)))

        try await assertIsolatedAndMuxSurvives(
            mux: mux,
            recorder: recorder,
            isolated: isolated,
            sibling: sibling,
            expectedReason: .flowControlError
        )
    }

    @Test func unknownWindowEmitsProtocolResetAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: 99, credit: 1)))

        try await expectResetFrame(in: recorder, streamID: 99, reason: .protocolError)
        try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
    }

    @Test func unknownDataEmitsProtocolResetAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildData(streamID: 99, payload: Data([0x01]))))

        try await expectResetFrame(in: recorder, streamID: 99, reason: .protocolError)
        try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
    }

    @Test func unknownStreamPingAndPongEmitProtocolResetAndMuxSurvives() async throws {
        for (streamID, flag) in [(UInt32(99), FrameFlags.ping.rawValue), (UInt32(101), FrameFlags.pong.rawValue)] {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
            let sibling = try await mux.openStream()
            await recorder.reset()

            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: streamID,
                flags: flag,
                payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
            )))

            try await expectResetFrame(in: recorder, streamID: streamID, reason: .protocolError)
            try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
            let next = try await mux.openStream()
            #expect(next.id == 3)
        }
    }

    @Test func unknownStreamPingDoesNotStopBufferedSiblingFrame() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let sibling = try await mux.openStream()
        await recorder.reset()
        var bytes = try encodeFrame(Frame(
            streamID: 99,
            flags: FrameFlags.ping.rawValue,
            payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
        ))
        bytes.append(try encodeFrame(buildData(streamID: sibling.id, payload: Data([0x5a]))))

        try await mux.feedInbound(bytes)

        try await expectResetFrame(in: recorder, streamID: 99, reason: .protocolError)
        #expect(try await readInboundPayload(from: sibling) == Data([0x5a]))
    }

    @Test func unknownCloseAndResetRemainSilentAndMuxSurvives() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(buildClose(streamID: 99)))
        try await mux.feedInbound(try encodeFrame(buildReset(streamID: 101, reason: .protocolError)))

        await expectNoResetFrames(in: recorder)
        try await sibling.write(Data([0xa5]))
        let data = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(data.streamID == sibling.id)
    }

    @Test func knownWindowDataCombinationIsolatesOnlyThatStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(rawMuxFrame(
            streamID: isolated.id,
            flags: FrameFlags.window.rawValue | FrameFlags.data.rawValue,
            payload: Data([0x00, 0x00, 0x00, 0x01])
        ))

        try await assertIsolatedAndMuxSurvives(
            mux: mux,
            recorder: recorder,
            isolated: isolated,
            sibling: sibling,
            expectedReason: .protocolError
        )
    }

    @Test func knownOpenResetCombinationIsolatesOnlyThatStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()

        try await mux.feedInbound(rawMuxFrame(
            streamID: isolated.id,
            flags: FrameFlags.open.rawValue | FrameFlags.reset.rawValue
        ))

        try await assertIsolatedAndMuxSurvives(
            mux: mux,
            recorder: recorder,
            isolated: isolated,
            sibling: sibling,
            expectedReason: .protocolError
        )
    }

    @Test func unknownInvalidCombinationEmitsProtocolReset() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(rawMuxFrame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.reset.rawValue
        ))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
        await expectNoIncomingStream(from: incoming)
    }

    @Test func invalidCombinationDoesNotStopBufferedSiblingFrame() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let isolated = try await mux.openStream()
        let sibling = try await mux.openStream()
        await recorder.reset()
        var bytes = rawMuxFrame(
            streamID: isolated.id,
            flags: FrameFlags.open.rawValue | FrameFlags.reset.rawValue
        )
        bytes.append(try encodeFrame(buildData(streamID: sibling.id, payload: Data([0x5a]))))

        try await mux.feedInbound(bytes)

        try await expectResetFrame(in: recorder, streamID: isolated.id, reason: .protocolError)
        #expect(try await readInboundPayload(from: sibling) == Data([0x5a]))
    }

    @Test func splitInvalidCombinationWaitsForCompletePayloadBeforeDispatch() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let frame = rawMuxFrame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.reset.rawValue,
            payload: Data([0x01])
        )

        try await mux.feedInbound(Data(frame.prefix(8)))
        await expectNoResetFrames(in: recorder)

        try await mux.feedInbound(Data(frame.dropFirst(8)))
        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
    }

    @Test func listenerOpenDataYieldsInitialPayload() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams
        let payload = Data([0x41, 0x42])

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: payload
        )))

        let stream = try await firstIncomingStream(from: incoming)
        #expect(stream.id == 1)
        #expect(try await readInboundPayload(from: stream) == payload)
    }

    @Test func listenerOpenWithPayloadYieldsInitialPayload() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams
        let payload = Data([0x43, 0x44])

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue,
            payload: payload
        )))

        let stream = try await firstIncomingStream(from: incoming)
        #expect(stream.id == 1)
        #expect(try await readInboundPayload(from: stream) == payload)
    }

    @Test func oversizeOpenPayloadResetsWithoutStreamState() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
        )))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .flowControlError)

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x01]))))
        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)

        await recorder.reset()
        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let stream = try await firstIncomingStream(from: incoming)
        #expect(stream.id == 1)
        await expectNoResetFrames(in: recorder)
    }

    @Test func duplicateOpenDataResetsWithoutReplacingExistingStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let stream = try await firstIncomingStream(from: incoming)
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: Data([0xd0])
        )))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
        await expectNoIncomingStream(from: incoming)

        await recorder.reset()
        try await stream.write(Data([0xa5]))
        let outboundData = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(outboundData.streamID == 1)

        try await mux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x5a]))))
        #expect(try await readInboundPayload(from: stream) == Data([0x5a]))
    }

    @Test func listenerOpenCloseYieldsEofWritableStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
            payload: Data()
        )))

        let stream = try await firstIncomingStream(from: incoming)
        #expect(stream.id == 1)
        #expect(try await inboundFinished(from: stream))
        await expectNoResetFrames(in: recorder)

        await recorder.reset()
        try await stream.write(Data([0xa5]))
        let data = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(data.streamID == 1)
        #expect(data.payload == Data([0xa5]))
    }

    @Test func listenerOpenCloseOversizePayloadResetsWithoutStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
            payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
        )))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .flowControlError)
        await expectNoIncomingStream(from: incoming)
    }

    @Test func duplicateOpenCloseResetsWithoutReplacingLiveStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
        let incoming = mux.incomingStreams

        try await mux.feedInbound(try encodeFrame(buildOpen(streamID: 1)))
        let stream = try await firstIncomingStream(from: incoming)
        await recorder.reset()

        try await mux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
            payload: Data([0xd0])
        )))

        try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
        await expectNoIncomingStream(from: incoming)

        await recorder.reset()
        try await stream.write(Data([0xa5]))
        let outboundData = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
        #expect(outboundData.streamID == 1)

        try await mux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x5a]))))
        #expect(try await readInboundPayload(from: stream) == Data([0x5a]))
    }

    @Test func composedOpenFlagsLegalOtherInvalidCombosStillReset() async throws {
        do {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
                payload: Data()
            )))
            _ = try await firstIncomingStream(from: mux.incomingStreams)
            await expectNoResetFrames(in: recorder)
        }

        do {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)
            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue | FrameFlags.close.rawValue,
                payload: Data([0x41])
            )))
            let stream = try await firstIncomingStream(from: mux.incomingStreams)
            #expect(try await readInboundPayload(from: stream) == Data([0x41]))
            await expectNoResetFrames(in: recorder)
        }

        for flag in [
            FrameFlags.close.rawValue | FrameFlags.reset.rawValue,
            FrameFlags.data.rawValue | FrameFlags.window.rawValue,
            FrameFlags.open.rawValue | FrameFlags.ping.rawValue,
        ] {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .listener)

            try await mux.feedInbound(rawMuxFrame(streamID: 1, flags: flag))

            try await expectResetFrame(in: recorder, streamID: 1, reason: .protocolError)
        }
    }

    @Test func unknownStreamResetSinkFailurePropagates() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.reset.rawValue))
        let mux = Multiplexer(sink: { bytes in try await sink.recordOrThrow(bytes) }, role: .dialer)

        do {
            try await mux.feedInbound(try encodeFrame(buildData(streamID: 99, payload: Data([0x01]))))
            Issue.record("Expected reset sink failure")
        } catch let error as MuxTestError {
            #expect(error == .sinkFailure)
        } catch {
            Issue.record("Expected reset sink failure, got \(error)")
        }

        #expect(await sink.matchingFrameCount(flags: FrameFlags.reset.rawValue) == 1)
    }

    @Test func openPayloadResetSinkFailurePropagates() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.reset.rawValue))
        let mux = Multiplexer(sink: { bytes in try await sink.recordOrThrow(bytes) }, role: .listener)

        do {
            try await mux.feedInbound(try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
                payload: Data(repeating: 0, count: Int(MuxConstants.initialCredit) + 1)
            )))
            Issue.record("Expected reset sink failure")
        } catch let error as MuxTestError {
            #expect(error == .sinkFailure)
        } catch {
            Issue.record("Expected reset sink failure, got \(error)")
        }

        #expect(await sink.matchingFrameCount(flags: FrameFlags.reset.rawValue) == 1)
    }

    @Test func unknownStreamPingResetsAndControlPingLengthRemainsFatal() async throws {
        let unknownRecorder = MuxFrameRecorder()
        let unknownMux = Multiplexer(sink: { bytes in try await unknownRecorder.record(bytes) }, role: .dialer)
        try await unknownMux.feedInbound(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.ping.rawValue,
            payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
        )))
        try await expectResetFrame(in: unknownRecorder, streamID: 1, reason: .protocolError)

        let controlRecorder = MuxFrameRecorder()
        let controlMux = Multiplexer(sink: { bytes in try await controlRecorder.record(bytes) }, role: .dialer)
        await expectFramingError(.lengthMismatch) {
            try await controlMux.feedInbound(try encodeFrame(Frame(
                streamID: 0,
                flags: FrameFlags.ping.rawValue,
                payload: Data([0x01])
            )))
        }
        await expectNoResetFrames(in: controlRecorder)
    }

    @Test func reservedBitAndMalformedStreamZeroFramesRemainFatal() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        await expectFramingError(.reservedBitsSet) {
            try await mux.feedInbound(rawMuxFrame(streamID: 1, flags: 0x80))
        }
        await expectNoResetFrames(in: recorder)

        let controlRecorder = MuxFrameRecorder()
        let controlMux = Multiplexer(sink: { bytes in try await controlRecorder.record(bytes) }, role: .dialer)
        await expectFramingError(.unknownControlFrame) {
            try await controlMux.feedInbound(rawMuxFrame(
                streamID: 0,
                flags: FrameFlags.ping.rawValue | FrameFlags.data.rawValue,
                payload: Data([1, 2, 3, 4, 5, 6, 7, 8])
            ))
        }
        let frames = await controlRecorder.frames()
        #expect(!frames.contains { $0.flags == FrameFlags.reset.rawValue })
        #expect(!frames.contains { $0.flags == FrameFlags.pong.rawValue })
    }

    @Test func tearDownThrowsOpenInboundAndBlocksOpenStream() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let streams = [
            try await mux.openStream(),
            try await mux.openStream(),
            try await mux.openStream(),
        ]

        await mux.tearDown(reason: .transportFailure)

        for stream in streams {
            var iterator = stream.inbound.makeAsyncIterator()
            await expectMuxError(.transportClosed) {
                _ = try await iterator.next()
            }
        }
        await expectMuxError(.transportClosed) {
            try await mux.openStream()
        }
    }

    @Test func dialerIncomingStreamsFinishOnTearDown() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        var iterator = mux.incomingStreams.makeAsyncIterator()

        await mux.tearDown(reason: .normalShutdown)

        #expect(await iterator.next() == nil)
    }

    @Test func controlPingEmitsPong() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)
        let nonce = Data([1, 2, 3, 4, 5, 6, 7, 8])

        try await mux.feedInbound(try encodeFrame(buildPing(nonce: nonce)))

        #expect(await recorder.frames() == [try buildPong(nonce: nonce)])
    }

    @Test func inboundActivityCounterIncrementsForDecodedFrames() async throws {
        let recorder = MuxFrameRecorder()
        let mux = Multiplexer(sink: { bytes in try await recorder.record(bytes) }, role: .dialer)

        #expect(await mux.inboundActivitySnapshot() == 0)
        try await mux.feedInbound(try encodeFrame(buildPing(nonce: Data([1, 2, 3, 4, 5, 6, 7, 8]))))
        #expect(await mux.inboundActivitySnapshot() == 1)
        try await mux.feedInbound(try encodeFrame(buildData(streamID: 1, payload: Data([0x01]))))
        #expect(await mux.inboundActivitySnapshot() == 2)
    }

    @Test func sendCreditCapCountsRemainingWindowNotLifetime() async throws {
        let recorder = MuxFrameRecorder()
        let stream = MuxStream(id: 1, sink: { bytes in try await recorder.record(bytes) }, onTerminal: { _ in })
        let roomToMax = UInt32(Int32.max) - MuxConstants.initialCredit

        #expect(await stream.grantSendCredit(roomToMax) == .accepted)
        #expect(await stream.grantSendCredit(1) == .flowControlExceeded)

        try await stream.write(Data(repeating: 0x41, count: MuxConstants.recommendedChunk))

        #expect(await stream.grantSendCredit(UInt32(MuxConstants.recommendedChunk)) == .accepted)
        #expect(await stream.grantSendCredit(1) == .flowControlExceeded)
    }

    @Test func cancelledWriteWaitingForCreditThrowsCancellationError() async throws {
        // proto/framing.md:124-129 zero-credit senders wait for WINDOW credit.
        let recorder = MuxFrameRecorder()
        let stream = MuxStream(id: 1, sink: { bytes in try await recorder.record(bytes) }, onTerminal: { _ in })
        try await stream.write(Data(repeating: 0x41, count: Int(MuxConstants.initialCredit)))
        let result = AsyncResultBox<Bool>()
        let writer = Task {
            do {
                try await stream.write(Data([0x42]))
                await result.store(false)
            } catch is CancellationError {
                await result.store(true)
            } catch {
                await result.store(false)
            }
        }

        let emittedWhileOutOfCredit = await conditionObserved {
            await recorder.count() > Int(MuxConstants.initialCredit) / MuxConstants.recommendedChunk
        }
        #expect(emittedWhileOutOfCredit == false)
        writer.cancel()
        let completed = await waitUntil("cancelled writer completed") {
            await result.snapshot() != nil
        }

        #expect(await result.snapshot() == true)
        if completed {
            await writer.value
        }
    }

    @Test func creditWaiterCancelledBeforeInstallStillResumes() async throws {
        // proto/framing.md:124-129 zero-credit senders do not emit DATA while waiting.
        let recorder = MuxFrameRecorder()
        let stream = MuxStream(id: 1, sink: { bytes in try await recorder.record(bytes) }, onTerminal: { _ in })
        try await stream.write(Data(repeating: 0x41, count: Int(MuxConstants.initialCredit)))
        let cancelledWriter = AsyncResultBox<Bool>()
        let writer = Task {
            do {
                try await stream.write(Data([0x42]))
                await cancelledWriter.store(false)
            } catch is CancellationError {
                await cancelledWriter.store(true)
            } catch {
                await cancelledWriter.store(false)
            }
        }
        writer.cancel()

        let writerCompleted = await waitUntil("immediately cancelled writer completed") {
            await cancelledWriter.snapshot() != nil
        }
        #expect(await cancelledWriter.snapshot() == true)
        if writerCompleted {
            await writer.value
        }

        let result = AsyncResultBox<Bool>()
        let probe = Task {
            do {
                let waiterID: UInt64 = 999
                await stream.prepareCreditWaiter(id: waiterID)
                await stream.cancelCreditWaiter(id: waiterID)
                try await stream.installCreditWaiter(id: waiterID)
                await result.store(false)
            } catch is CancellationError {
                await result.store(true)
            } catch {
                await result.store(false)
            }
        }

        await waitUntil("pre-install cancelled waiter resumed") {
            await result.snapshot() != nil
        }

        #expect(await result.snapshot() == true)
        await probe.value
    }

    @Test func muxErrorEquatableCoversFlowControlErrorAndTypedReset() {
        #expect(MuxError.flowControlError == .flowControlError)
        #expect(MuxError.streamReset(streamID: 1, reason: .cancel, rawByte: 0x05) ==
            .streamReset(streamID: 1, reason: .cancel, rawByte: 0x05))
    }
}
