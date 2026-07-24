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
        #expect(try Crockford32.decode(Self.encode(bytes)) == bytes)
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

    private static func encode(_ bytes: [UInt8]) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var accumulator: UInt64 = 0
        var bitCount = 0
        var output = ""

        for byte in bytes {
            accumulator = (accumulator << 8) | UInt64(byte)
            bitCount += 8

            while bitCount >= 5 {
                bitCount -= 5
                let index = Int((accumulator >> UInt64(bitCount)) & 0x1f)
                output.append(alphabet[index])
                accumulator &= (1 << UInt64(bitCount)) - 1
            }
        }

        if bitCount > 0 {
            let index = Int((accumulator << UInt64(5 - bitCount)) & 0x1f)
            output.append(alphabet[index])
        }

        return output
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
