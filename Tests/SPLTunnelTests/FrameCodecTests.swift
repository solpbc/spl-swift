// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

private enum Fixtures {
    static let open1: [UInt8] = [
        0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    ]
    static let openMax: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    ]
    static let dataA: [UInt8] = [
        0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x41,
    ]
    static let dataEmpty: [UInt8] = [
        0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00,
    ]
    static let data64KiB: Data = {
        var data = Data([0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x00, 0x00])
        data.append(Data(repeating: 0, count: 64 * 1024))
        return data
    }()
    static let close1: [UInt8] = [
        0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
    ]
    static let resetProtocolError: [UInt8] = [
        0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x01, 0x01,
    ]
    static let resetFlowControlError: [UInt8] = [
        0x00, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x01, 0x02,
    ]
    static let window64KiB: [UInt8] = [
        0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x00,
    ]
    static let ping: [UInt8] = [
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]
    static let pong: [UInt8] = [
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]
    static let dataFourBytes: [UInt8] = [
        0x00, 0x00, 0x00, 0x09, 0x02, 0x00, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04,
    ]
}

@Suite("FrameCodecWireCompat")
struct FrameCodecWireCompatTests {
    @Test func openStreamOne() throws {
        try expectFixture(buildOpen(streamID: 1), bytes: Data(Fixtures.open1))
    }

    @Test func openMaxStreamID() throws {
        try expectFixture(buildOpen(streamID: 0xffff_ffff), bytes: Data(Fixtures.openMax))
    }

    @Test func dataOneByte() throws {
        try expectFixture(buildData(streamID: 1, payload: Data([0x41])), bytes: Data(Fixtures.dataA))
    }

    @Test func dataEmptyPayload() throws {
        try expectFixture(buildData(streamID: 3, payload: Data()), bytes: Data(Fixtures.dataEmpty))
    }

    @Test func data64KiBPayload() throws {
        try expectFixture(
            buildData(streamID: 5, payload: Data(repeating: 0, count: 64 * 1024)),
            bytes: Fixtures.data64KiB
        )
    }

    @Test func closeStreamOne() throws {
        try expectFixture(buildClose(streamID: 1), bytes: Data(Fixtures.close1))
    }

    @Test func resetProtocolError() throws {
        try expectFixture(
            buildReset(streamID: 1, reason: .protocolError),
            bytes: Data(Fixtures.resetProtocolError)
        )
    }

    @Test func resetFlowControlError() throws {
        try expectFixture(
            buildReset(streamID: 7, reason: .flowControlError),
            bytes: Data(Fixtures.resetFlowControlError)
        )
    }

    @Test func resetReasonsRoundTripAndUnknownReasonsAreUnspecified() throws {
        let reasons: [ResetReason] = [
            .protocolError,
            .flowControlError,
            .streamLimitExceeded,
            .internalError,
            .cancel,
            .unspecified,
        ]

        for reason in reasons {
            let frame = buildReset(streamID: 1, reason: reason)

            var decoder = FrameDecoder()
            decoder.feed(try encodeFrame(frame))
            let decoded = try #require(try decoder.next())
            #expect(parseResetReason(from: decoded.payload).reason == reason)
            #expect(try decoder.next() == nil)
        }

        var unknownDecoder = FrameDecoder()
        unknownDecoder.feed(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.reset.rawValue,
            payload: Data([0x42])
        )))
        let unknown = try #require(try unknownDecoder.next())
        #expect(parseResetReason(from: unknown.payload).reason == .unspecified)

        var emptyDecoder = FrameDecoder()
        emptyDecoder.feed(try encodeFrame(Frame(
            streamID: 1,
            flags: FrameFlags.reset.rawValue,
            payload: Data()
        )))
        let empty = try #require(try emptyDecoder.next())
        #expect(parseResetReason(from: empty.payload).reason == .unspecified)
    }

    @Test func window64KiBCredit() throws {
        try expectFixture(buildWindow(streamID: 1, credit: 0x0001_0000), bytes: Data(Fixtures.window64KiB))
    }

    @Test func pingRoundTrip() throws {
        try expectFixture(buildPing(nonce: Data([1, 2, 3, 4, 5, 6, 7, 8])), bytes: Data(Fixtures.ping))
    }

    @Test func pongRoundTrip() throws {
        try expectFixture(buildPong(nonce: Data([1, 2, 3, 4, 5, 6, 7, 8])), bytes: Data(Fixtures.pong))
    }

    @Test func dataFourBytes() throws {
        try expectFixture(
            buildData(streamID: 9, payload: Data([0x01, 0x02, 0x03, 0x04])),
            bytes: Data(Fixtures.dataFourBytes)
        )
    }

    @Test func parseResetReasonToleratesEmptyLongAndUnknownPayloads() {
        // proto/framing.md is silent on an absent RESET payload; this pins client behavior.
        let empty = parseResetReason(from: Data())
        #expect(empty.reason == .unspecified)
        #expect(empty.rawByte == 0x00)

        let knownLong = parseResetReason(from: Data([0x05, 0x01]))
        #expect(knownLong.reason == .cancel)
        #expect(knownLong.rawByte == 0x05)

        let unknown = parseResetReason(from: Data([0x7e]))
        #expect(unknown.reason == .unspecified)
        #expect(unknown.rawByte == 0x7e)

        let unknownLong = parseResetReason(from: Data([0x00, 0x00, 0x00, 0x01]))
        #expect(unknownLong.reason == .unspecified)
        #expect(unknownLong.rawByte == 0x00)
    }

    private func expectFixture(_ frame: Frame, bytes: Data) throws {
        let encoded = try encodeFrame(frame)
        #expect(encoded == bytes)

        var decoder = FrameDecoder()
        decoder.feed(bytes)
        let decoded = try #require(try decoder.next())
        #expect(decoded == frame)
        #expect(try decoder.next() == nil)
    }
}

@Suite("FrameCodecValidation")
struct FrameCodecValidationTests {
    @Test func payloadTooLargeThrows() {
        expectThrows(.payloadTooLarge) {
            _ = try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.data.rawValue,
                payload: Data(repeating: 0, count: FramingLimits.maxPayload + 1)
            ))
        }
    }

    @Test func reservedBitsThrow() {
        expectThrows(.reservedBitsSet) {
            try validateFlags(0xe0)
        }
    }

    @Test func noPrimaryFlagThrows() {
        expectThrows(.noPrimaryFlag) {
            try validateFlags(0x00)
        }
    }

    @Test func openResetThrows() {
        expectThrows(.invalidFlagCombination) {
            try validateFlags(FrameFlags.open.rawValue | FrameFlags.reset.rawValue)
        }
    }

    @Test func openDataCloseValidates() throws {
        let frame = Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue | FrameFlags.close.rawValue,
            payload: Data([0x41])
        )
        try validateFlags(frame.flags)

        var decoder = FrameDecoder()
        decoder.feed(try encodeFrame(frame))
        #expect(try decoder.next() == frame)
        #expect(try decoder.next() == nil)
    }

    @Test func pingDataThrows() {
        expectThrows(.invalidFlagCombination) {
            try validateFlags(FrameFlags.ping.rawValue | FrameFlags.data.rawValue)
        }
    }

    @Test func windowDataThrows() {
        expectThrows(.invalidFlagCombination) {
            try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.window.rawValue | FrameFlags.data.rawValue,
                payload: Data([0x00, 0x00, 0x00, 0x01])
            ))
        }
    }

    @Test func dataResetThrows() {
        expectThrows(.invalidFlagCombination) {
            try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.data.rawValue | FrameFlags.reset.rawValue,
                payload: Data([0x01])
            ))
        }
    }

    @Test func openCloseValidates() throws {
        let frame = Frame(
            streamID: 1,
            flags: FrameFlags.open.rawValue | FrameFlags.close.rawValue,
            payload: Data()
        )
        try validateFlags(frame.flags)

        var decoder = FrameDecoder()
        decoder.feed(try encodeFrame(frame))
        #expect(try decoder.next() == frame)
        #expect(try decoder.next() == nil)
    }

    @Test func invalidControlNonceLengthThrows() {
        expectThrows(.lengthMismatch) {
            _ = try buildPing(nonce: Data([0x01]))
        }
    }

    @Test func invalidWindowCreditLengthThrows() {
        expectThrows(.lengthMismatch) {
            _ = try parseWindowCredit(from: Data([0x00, 0x01]))
        }
    }

    @Test func invalidControlNonceParseLengthThrows() {
        expectThrows(.lengthMismatch) {
            _ = try parseControlNonce(from: Data([0x01]))
        }
    }
}

@Suite("FrameDecoderIncremental")
struct FrameDecoderIncrementalTests {
    @Test func threeFramesInOneByteChunks() throws {
        let frames = [
            buildOpen(streamID: 1),
            buildData(streamID: 1, payload: Data([0x41])),
            buildClose(streamID: 1),
        ]
        let bytes = try frames.reduce(into: Data()) { partial, frame in
            partial.append(try encodeFrame(frame))
        }

        var decoded: [Frame] = []
        var decoder = FrameDecoder()
        for byte in bytes {
            decoder.feed(Data([byte]))
            while let frame = try decoder.next() {
                decoded.append(frame)
            }
        }

        #expect(decoded == frames)
        #expect(try decoder.next() == nil)
    }

    @Test func boundedRetentionAcrossLongMultiFrameStream() throws {
        let frameCount = 20_000
        let payloadSize = 16
        let chunkSize = 31
        let encodedFrameSize = 8 + payloadSize
        let frames = (0..<frameCount).map { index in
            Frame(
                streamID: UInt32(index + 1),
                flags: FrameFlags.data.rawValue,
                payload: Data(repeating: UInt8(index & 0xff), count: payloadSize)
            )
        }
        let bytes = try frames.reduce(into: Data()) { partial, frame in
            partial.append(try encodeFrame(frame))
        }

        var decoded: [Frame] = []
        decoded.reserveCapacity(frameCount)
        var decoder = FrameDecoder()
        var maxRetainedAfterDrain = 0
        var cursor = bytes.startIndex
        while cursor < bytes.endIndex {
            let next = bytes.index(cursor, offsetBy: chunkSize, limitedBy: bytes.endIndex) ?? bytes.endIndex
            decoder.feed(Data(bytes[cursor..<next]))
            while let frame = try decoder.next() {
                decoded.append(frame)
            }
            maxRetainedAfterDrain = max(maxRetainedAfterDrain, decoder.retainedBufferByteCount)
            cursor = next
        }

        #expect(decoded == frames)
        #expect(try decoder.next() == nil)
        let highWaterBound = (64 << 10) + encodedFrameSize + chunkSize
        let steadyStateRetentionBound = 2 * (encodedFrameSize - 1)
        // The high-water bound covers the 64 KiB compaction branch. Without compaction,
        // the high-water mark would equal the full stream size.
        #expect(decoder.bufferHighWaterMark <= highWaterBound)
        #expect(highWaterBound < bytes.count / 4)
        #expect(bytes.count > highWaterBound)
        // The steady-state bound covers the half-buffer branch: after a drain,
        // unread tail < one 24-byte frame and retained consumed bytes <= that tail,
        // so retained buffer <= two partial frames. The 31-byte chunk is already drained.
        #expect(maxRetainedAfterDrain <= steadyStateRetentionBound)
    }

    @Test func singleLargeFrameOneByteFeedsRetainsOnlyInFlightFrame() throws {
        let payloadSize = 1 << 20
        let frame = buildData(streamID: 1, payload: Data(repeating: 0, count: payloadSize))
        let bytes = try encodeFrame(frame)
        var decoder = FrameDecoder()

        for byte in bytes {
            decoder.feed(Data([byte]))
        }

        #expect(decoder.bufferHighWaterMark == bytes.count)
        #expect(decoder.retainedBufferByteCount == bytes.count)
        let decoded = try #require(try decoder.next())
        #expect(decoded == frame)
        #expect(decoder.retainedBufferByteCount == 0)
        #expect(try decoder.next() == nil)
    }
}

private func expectThrows<T>(_ expected: FramingError, _ operation: () throws -> T) {
    do {
        _ = try operation()
        Issue.record("Expected \(expected)")
    } catch let error as FramingError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), got \(error)")
    }
}
