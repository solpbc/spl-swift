// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("Crockford32")
struct Crockford32Tests {
    @Test func emptyStringDecodesToEmptyBytes() throws {
        #expect(try Crockford32.decode("") == [])
    }

    @Test func byteRoundTrip() throws {
        let bytes = Array(UInt8.min...UInt8.max)
        #expect(try Crockford32.decode(Crockford32TestEncoding.encode(bytes)) == bytes)
    }

    @Test func lowercaseFoldsToUppercase() throws {
        let lowercase = "080w000258dsx8djrfaebxg733favfqfsbzbnfg14d2pf2dbsqqg"
        #expect(try Crockford32.decode(lowercase) == Crockford32.decode(lowercase.uppercased()))
    }

    @Test func ambiguousCharactersFold() throws {
        let oneExpected = try Crockford32.decode("10")
        #expect(try Crockford32.decode("I0") == oneExpected)
        #expect(try Crockford32.decode("i0") == oneExpected)
        #expect(try Crockford32.decode("l0") == oneExpected)
        #expect(try Crockford32.decode("L0") == oneExpected)

        let zeroExpected = try Crockford32.decode("00")
        #expect(try Crockford32.decode("O0") == zeroExpected)
        #expect(try Crockford32.decode("o0") == zeroExpected)
    }

    @Test func hyphenAndWhitespaceAreIgnored() throws {
        #expect(try Crockford32.decode("080W0002") == Crockford32.decode("08 0W-00\n02"))
    }

    @Test func questionMarkIsRejectedAsOutOfAlphabet() {
        expectThrows(.outOfAlphabet("?")) {
            _ = try Crockford32.decode("?")
        }
    }

    @Test func nonCanonicalPadBitsAreRejected() {
        let canonical = "080W000258DSX8DJRFAEBXG733FAVFQFSBZBNFG14D2PF2DBSQQG"
        let nonCanonical = String(canonical.dropLast()) + "H"

        expectThrows(.nonCanonicalPadBits) {
            _ = try Crockford32.decode(nonCanonical)
        }
        expectThrows(.nonCanonicalPadBits) {
            _ = try Crockford32.decode("1")
        }
    }

    @Test func singleZeroPadBitsDecodeToEmptyBytes() throws {
        #expect(try Crockford32.decode("0") == [])
    }

    @Test func validPairURLBlobsRoundTripThroughParser() throws {
        var generator = LCG(state: 0xDEADBEEF)

        for _ in 0..<128 {
            var bytes = (0..<40).map { _ in generator.nextByte() }
            bytes[0] = 0x04
            bytes[1] = 0x01

            let fragment = Crockford32TestEncoding.encode(bytes)
            let pairURL = try PairURL.parse(URL(string: "https://go.solstone.app/p#\(fragment)")!)
            #expect(pairURL.version == bytes[0])
            #expect(pairURL.kind == .direct)
            #expect(pairURL.candidates.first?.address == Array(bytes[2..<6]).map(String.init).joined(separator: "."))
            #expect(pairURL.candidates.first?.port == UInt16(bytes[6]) << 8 | UInt16(bytes[7]))
            #expect(pairURL.nonceBytes == Array(bytes[8..<24]))
            #expect(pairURL.caFingerprintBytes == Array(bytes[24..<40]))
        }
    }

    private func expectThrows(_ expected: Crockford32Error, _ operation: () throws -> Void) {
        do {
            try operation()
            Issue.record("Expected \(expected)")
        } catch let error as Crockford32Error {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}

private struct LCG {
    var state: UInt64

    mutating func nextByte() -> UInt8 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return UInt8((state >> 56) & 0xff)
    }
}
