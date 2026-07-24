// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("FramingConformance")
struct FramingConformanceTests {
    @Test func headerLayoutEncodesBigEndianFields() throws {
        // proto/framing.md:13,29-34 pins the 8-byte header as stream_id u32, flags u8, length u24.
        let frame = Frame(streamID: 0x0102_0304, flags: FrameFlags.data.rawValue, payload: Data([0xaa, 0xbb, 0xcc]))

        let encoded = try encodeFrame(frame)

        #expect(encoded == Data([
            0x01, 0x02, 0x03, 0x04,
            0x02,
            0x00, 0x00, 0x03,
            0xaa, 0xbb, 0xcc,
        ]))
    }

    @Test func maximumPayloadIsSixteenMiBMinusOne() {
        // proto/framing.md:33,36 pins the u24 length maximum as 16 MiB minus 1.
        #expect(FramingLimits.maxPayload == 0x00ff_ffff)
        expectThrows(.payloadTooLarge) {
            _ = try encodeFrame(Frame(
                streamID: 1,
                flags: FrameFlags.data.rawValue,
                payload: Data(repeating: 0, count: FramingLimits.maxPayload + 1)
            ))
        }
    }

    @Test func flagBitsMatchProtocolTable() {
        // proto/framing.md:42-51 pins each flag bit value.
        #expect(FrameFlags.open.rawValue == 0x01)
        #expect(FrameFlags.data.rawValue == 0x02)
        #expect(FrameFlags.close.rawValue == 0x04)
        #expect(FrameFlags.reset.rawValue == 0x08)
        #expect(FrameFlags.window.rawValue == 0x10)
        #expect(FrameFlags.ping.rawValue == 0x20)
        #expect(FrameFlags.pong.rawValue == 0x40)
        #expect(FrameFlags.reservedMask == 0x80)
    }

    @Test func everyFlagCombinationAcrossZeroToSevenF() {
        // proto/framing.md:53-58,60 pins singleton flags plus the four legal compositions.
        let valid: Set<UInt8> = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x20, 0x40,
        ]

        for raw in UInt8(0)...UInt8(0x7f) {
            if raw == 0 {
                expectThrows(.noPrimaryFlag) {
                    try validateFlags(raw)
                }
            } else if valid.contains(raw) {
                do {
                    try validateFlags(raw)
                } catch {
                    Issue.record("Expected flags \(raw) to validate, got \(error)")
                }
            } else {
                expectThrows(.invalidFlagCombination) {
                    try validateFlags(raw)
                }
            }
        }
    }

    @Test func reservedBitRejectedAtEncodeAndDecode() {
        // proto/framing.md:51 says receivers MUST reject frames with bit 7 set.
        expectThrows(.reservedBitsSet) {
            try validateFlags(0x82)
        }
        expectThrows(.reservedBitsSet) {
            _ = try encodeFrame(Frame(streamID: 1, flags: 0x82, payload: Data()))
        }

        var decoder = FrameDecoder()
        decoder.feed(Self.rawFrame(streamID: 1, flags: 0x82))
        expectThrows(.reservedBitsSet) {
            _ = try decoder.next()
        }
    }

    @Test func openPayloadIsOrdinaryStreamBytes() throws {
        // proto/framing.md:60 makes OPEN payload ordinary stream bytes; Mux enforces window debit later.
        let open = Frame(streamID: 1, flags: FrameFlags.open.rawValue, payload: Data([0x41]))
        let openData = Frame(
            streamID: 3,
            flags: FrameFlags.open.rawValue | FrameFlags.data.rawValue,
            payload: Data([0x42, 0x43])
        )

        for frame in [open, openData] {
            try validateFlags(frame.flags)
            var decoder = FrameDecoder()
            decoder.feed(try encodeFrame(frame))
            #expect(try decoder.next() == frame)
            #expect(try decoder.next() == nil)
        }
    }

    @Test func resetReasonCodesMatchProtocolTable() {
        // proto/framing.md:62-71 pins reset reason byte values.
        #expect(ResetReason.protocolError.rawValue == 0x01)
        #expect(ResetReason.flowControlError.rawValue == 0x02)
        #expect(ResetReason.streamLimitExceeded.rawValue == 0x03)
        #expect(ResetReason.internalError.rawValue == 0x04)
        #expect(ResetReason.cancel.rawValue == 0x05)
        #expect(ResetReason.unspecified.rawValue == 0xff)
    }

    @Test func unknownResetReasonNormalizesToUnspecified() {
        // proto/framing.md:73 says unknown reason codes are treated as UNSPECIFIED.
        let parsed = parseResetReason(from: Data([0x7e]))

        #expect(parsed.reason == .unspecified)
        #expect(parsed.rawByte == 0x7e)
    }

    private static func rawFrame(streamID: UInt32, flags: UInt8, payload: Data = Data()) -> Data {
        var data = Data()
        data.reserveCapacity(8 + payload.count)
        data.append(UInt8((streamID >> 24) & 0xff))
        data.append(UInt8((streamID >> 16) & 0xff))
        data.append(UInt8((streamID >> 8) & 0xff))
        data.append(UInt8(streamID & 0xff))
        data.append(flags)
        data.append(UInt8((payload.count >> 16) & 0xff))
        data.append(UInt8((payload.count >> 8) & 0xff))
        data.append(UInt8(payload.count & 0xff))
        data.append(payload)
        return data
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
