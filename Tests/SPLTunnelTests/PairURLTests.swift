// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("PairURL")
struct PairURLTests {
    // proto/pairing.md:84-96 specifies the 0x05 multi-candidate direct form.
    // These tests pin parser behavior; conformance vectors live under Conformance/.
    @Test func multiAddressReferenceVectorParses() throws {
        let pairURL = try PairURL.parse(Self.url(fragment: Self.multiAddressBlob))

        #expect(pairURL.version == 0x05)
        #expect(pairURL.kind == .direct)
        #expect(pairURL.candidates == [
            PairCandidate(address: "192.0.2.10", port: 7657),
            PairCandidate(address: "198.51.100.20", port: 7657),
        ])
        #expect(pairURL.nonceBytes == (0x00...0x0F).map(UInt8.init))
        #expect(pairURL.caFingerprintBytes == (0xA0...0xAF).map(UInt8.init))
        #expect(pairURL.caPin.kind == .certificateSHA256)
        #expect(pairURL.sBytes == [])
        #expect(pairURL.relayOrigin == nil)
    }

    @Test func multiAddressReferenceVectorReconstructsExactBlob() throws {
        let pairURL = try PairURL.parse(Self.url(fragment: Self.multiAddressBlob))

        #expect(Self.hex(Self.reconstructedMultiBytes(from: pairURL)) == Self.multiAddressHex)
    }

    @Test func alternateV04VectorParsesOneCandidate() throws {
        let pairURL = try PairURL.parse(Self.url(fragment: Self.alternateDirectBlob))

        #expect(pairURL.version == 0x04)
        #expect(pairURL.candidates == [PairCandidate(address: "192.0.2.10", port: 7657)])
    }

    @Test func rejectsWrongScheme() {
        expectThrows(.wrongScheme("http")) {
            _ = try PairURL.parse(URL(string: "http://go.solstone.app/p#\(Self.canonicalBlob)")!)
        }
    }

    @Test func rejectsWrongHost() {
        expectThrows(.wrongHost("example.com")) {
            _ = try PairURL.parse(URL(string: "https://example.com/p#\(Self.canonicalBlob)")!)
        }
    }

    @Test func rejectsWrongPath() {
        expectThrows(.wrongPath("/wrong")) {
            _ = try PairURL.parse(URL(string: "https://go.solstone.app/wrong#\(Self.canonicalBlob)")!)
        }
    }

    @Test func rejectsMissingFragment() {
        expectThrows(.missingFragment) {
            _ = try PairURL.parse(URL(string: "https://go.solstone.app/p")!)
        }
    }

    @Test func rejectsInvalidBase32() {
        expectThrows(.invalidBase32(.outOfAlphabet("?"))) {
            _ = try PairURL.parse(Self.url(fragment: "?"))
        }
    }

    @Test func rejectsInvalidVersion() {
        var bytes = Self.canonicalBytes
        bytes[0] = 0x01

        expectThrows(.invalidVersion(0x01)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsLegacyDirectFragment() {
        let legacyBytes: [UInt8] = [
            0x02, 0x01, 0xC0, 0x00, 0x02, 0x2A, 0x1B, 0x9E,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]

        expectThrows(.invalidVersion(0x02)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(legacyBytes)))
        }
    }

    @Test func rejectsIPv4AddressTypeWithLength39() {
        var bytes = Self.canonicalBytes
        bytes.removeLast()

        expectThrows(.invalidLength(39)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsIPv4AddressTypeWithLength41() {
        var bytes = Self.canonicalBytes
        bytes.append(0x00)

        expectThrows(.invalidLength(41)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsReservedIPv6AddressType() {
        var bytes = Self.canonicalBytes
        bytes[1] = 0x02

        expectThrows(.unsupportedAddrType(0x02)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsUnknownAddressType() {
        var bytes = Self.canonicalBytes
        bytes[1] = 0x03

        expectThrows(.unsupportedAddrType(0x03)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsRelayUnsupportedFingerprintTag() {
        var bytes = Self.relayBytes()
        bytes[9] = 0x02

        expectThrows(.unsupportedCAFingerprintTag(0x02)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsRelaySelectorLengthMismatch() {
        var bytes = Self.relayBytes()
        bytes[26] = 0x04

        expectThrows(.invalidLength(27)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsRelayInvalidOrigin() {
        let bytes = Self.relayBytes(origin: "ftp://relay.example")

        expectThrows(.invalidRelayOrigin) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsPlaintextCustomRelayOrigin() throws {
        for origin in ["http://relay.example", "ws://relay.example"] {
            expectThrows(.invalidRelayOrigin) {
                _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(Self.relayBytes(origin: origin))))
            }
        }

        let https = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(Self.relayBytes(origin: "https://relay.example"))))
        let wss = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(Self.relayBytes(origin: "wss://relay.example"))))
        let wellKnown = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(Self.relayBytes())))

        #expect(https.relayOrigin == .custom(URL(string: "https://relay.example")!))
        #expect(wss.relayOrigin == .custom(URL(string: "wss://relay.example")!))
        #expect(wellKnown.relayOrigin == .wellKnown)
    }

    @Test func rejectsMultiAddressZeroCount() {
        var bytes = Self.multiAddressBytes
        bytes[2] = 0

        expectThrows(.invalidLength(bytes.count)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsMultiAddressTruncatedLength() {
        var bytes = Self.multiAddressBytes
        bytes.removeLast()

        expectThrows(.invalidLength(bytes.count)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsMultiAddressExtraByte() {
        var bytes = Self.multiAddressBytes
        bytes.append(0x00)

        expectThrows(.invalidLength(bytes.count)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsMultiAddressUnsupportedAddressType() {
        var bytes = Self.multiAddressBytes
        bytes[1] = 0x02

        expectThrows(.unsupportedAddrType(0x02)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsFutureVersion() {
        var bytes = Self.multiAddressBytes
        bytes[0] = 0x07

        expectThrows(.invalidVersion(0x07)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    @Test func rejectsLegacyRelayVersion() {
        var bytes = Self.relayBytes()
        bytes[0] = 0x03

        expectThrows(.invalidVersion(0x03)) {
            _ = try PairURL.parse(Self.url(fragment: Crockford32TestEncoding.encode(bytes)))
        }
    }

    private static let canonicalBlob = "0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF"
    private static let alternateDirectBlob = "0G0W000218EYJ001081G81860W40J2GB1G6GW3X0M6HA7955MTKTHADANEPAVBNF"
    private static let multiAddressBlob = "0M0G47F9R00042P66DJ18001081G81860W40J2GB1G6GW3X0M6HA7955MTKTHADANEPAVBNF"
    private static let multiAddressHex = "0501021de9c000020ac6336414000102030405060708090a0b0c0d0e0fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    private static let relaySBytes: [UInt8] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ]
    private static let relayCAFingerprintBytes: [UInt8] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ]
    private static let canonicalBytes: [UInt8] = [
        0x04, 0x01, 0xC0, 0x00, 0x02, 0x2A, 0x1B, 0x9E,
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ]
    private static let multiAddressBytes: [UInt8] = [
        0x05, 0x01, 0x02, 0x1D, 0xE9,
        0xC0, 0x00, 0x02, 0x0A,
        0xC6, 0x33, 0x64, 0x14,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    ]

    private static func url(fragment: String) -> URL {
        URL(string: "https://go.solstone.app/p#\(fragment)")!
    }

    private static func relayBytes(origin: String? = nil) -> [UInt8] {
        let originBytes = origin.map { Array($0.utf8) } ?? []
        let selector = origin.map { _ in UInt8(originBytes.count) } ?? 0
        return [
            0x06,
        ] + relaySBytes + [
            0x01,
        ] + relayCAFingerprintBytes + [
            selector,
        ] + originBytes
    }

    private static func reconstructedMultiBytes(from pairURL: PairURL) -> [UInt8] {
        guard let first = pairURL.candidates.first else {
            return []
        }
        var bytes: [UInt8] = [
            pairURL.version,
            0x01,
            UInt8(pairURL.candidates.count),
            UInt8(first.port >> 8),
            UInt8(first.port & 0x00FF),
        ]
        for candidate in pairURL.candidates {
            bytes.append(contentsOf: candidate.address.split(separator: ".").map { UInt8($0)! })
        }
        bytes.append(contentsOf: pairURL.nonceBytes)
        bytes.append(contentsOf: pairURL.caFingerprintBytes)
        return bytes
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func expectThrows(_ expected: PairURLError, _ operation: () throws -> Void) {
        do {
            try operation()
            Issue.record("Expected \(expected)")
        } catch let error as PairURLError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}
