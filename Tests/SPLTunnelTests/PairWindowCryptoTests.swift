// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Testing

@Suite("PairWindowCrypto")
struct PairWindowCryptoTests {
    @Test func relayKeyMatchesProtocolVector() throws {
        // proto/pair-window.md:44-48 pins S as the 8 bytes hex-decoded from "0123456789abcdef".
        let sBytes: [UInt8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]

        let relayKey = try PairWindowRelayKey(sBytes: sBytes)

        #expect(relayKey.secPairKeyHeaderValue == "e34481a4cde647ba9c9fb29a59e18271")
    }

    @Test func nonEightByteSThrowsInvalidLength() {
        let cases: [[UInt8]] = [
            [],
            Array(repeating: 0, count: 7),
            Array(repeating: 0, count: 16),
        ]

        for bytes in cases {
            expectInvalidSLength(bytes)
        }
    }

    private func expectInvalidSLength(_ bytes: [UInt8]) {
        do {
            _ = try PairWindowRelayKey(sBytes: bytes)
            Issue.record("Expected invalidSLength")
        } catch let error as PairWindowRelayKeyError {
            #expect(error == .invalidSLength(actual: bytes.count))
        } catch {
            Issue.record("Expected invalidSLength, got \(error)")
        }
    }
}
