// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("PairLinkConformance")
struct PairLinkConformanceTests {
    @Test func directVectorParsesToProtocolFields() throws {
        // proto/pairing.md:65-74,78,81 pins the 0x04 field table and reference link.
        let pairURL = try PairURL.parse(URL(string: Self.directLink)!)

        #expect(pairURL.version == 0x04)
        #expect(pairURL.kind == .direct)
        #expect(pairURL.candidates == [PairCandidate(address: "192.0.2.42", port: 7070)])
        #expect(pairURL.nonceBytes == [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ])
        #expect(pairURL.caFingerprintBytes == [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ])
        #expect(pairURL.caPin.kind == .certificateSHA256)
        #expect(pairURL.sBytes == [])
        #expect(pairURL.relayOrigin == nil)
    }

    @Test func defaultRelayVectorIsByteIdentical() throws {
        // proto/pair-window.md:28-37,39-45,53-55,66 pins the default relay vector bytes.
        let expectedBlob = try Self.bytes(hex: Self.defaultRelayBlobHex)

        #expect(try Crockford32.decode(Self.defaultRelayFragment) == expectedBlob)
        #expect(Self.defaultRelayLink == "https://go.solstone.app/p#\(Self.defaultRelayFragment)")

        let pairURL = try PairURL.parse(URL(string: Self.defaultRelayLink)!)
        #expect(pairURL.version == 0x06)
        #expect(pairURL.kind == .relay)
        #expect(pairURL.sBytes == Self.sBytes)
        #expect(pairURL.nonceBytes == [])
        #expect(pairURL.caPin.kind == .spkiSHA256)
        #expect(pairURL.caFingerprintBytes == Self.caFingerprintBytes)
        #expect(pairURL.candidates == [])
        #expect(pairURL.relayOrigin == .wellKnown)
    }

    @Test func customRelayVectorIsByteIdentical() throws {
        // proto/pair-window.md:28-37,39-45,61-63,66 pins the custom relay vector bytes.
        let expectedBlob = try Self.bytes(hex: Self.customRelayBlobHex)

        #expect(try Crockford32.decode(Self.customRelayFragment) == expectedBlob)
        #expect(Self.customRelayLink == "https://go.solstone.app/p#\(Self.customRelayFragment)")

        let pairURL = try PairURL.parse(URL(string: Self.customRelayLink)!)
        #expect(pairURL.version == 0x06)
        #expect(pairURL.kind == .relay)
        #expect(pairURL.sBytes == Self.sBytes)
        #expect(pairURL.caPin.kind == .spkiSHA256)
        #expect(pairURL.caFingerprintBytes == Self.caFingerprintBytes)
        #expect(pairURL.relayOrigin == .custom(URL(string: "https://relay.example")!))
    }

    @Test func wellKnownSelectorCarriesNoBakedOrigin() throws {
        // proto/pair-window.md:35,37 pins selector 0x00 as omitted relay_origin plus well-known default.
        let pairURL = try PairURL.parse(URL(string: Self.defaultRelayLink)!)

        #expect(pairURL.relayOrigin == .wellKnown)
        let override = URL(string: "https://relay.test")!
        #expect(pairURL.relayOrigin?.resolved(default: override) == override)
    }

    private static let directLink = "https://go.solstone.app/p#0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF"
    private static let defaultRelayBlobHex = "060123456789abcdef01deadbeefcafebabe0123456789abcdef00"
    private static let defaultRelayFragment = "0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00"
    private static let defaultRelayLink = "https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00"
    private static let customRelayBlobHex = "060123456789abcdef01deadbeefcafebabe0123456789abcdef1568747470733a2f2f72656c61792e6578616d706c65"
    private static let customRelayFragment = "0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A"
    private static let customRelayLink = "https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A"
    private static let sBytes: [UInt8] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]
    private static let caFingerprintBytes: [UInt8] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]

    private static func bytes(hex: String) throws -> [UInt8] {
        #expect(hex.count.isMultiple(of: 2))
        var output: [UInt8] = []
        output.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            let byte = try #require(UInt8(hex[index..<next], radix: 16))
            output.append(byte)
            index = next
        }
        return output
    }
}
