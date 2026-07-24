// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
@testable import SPLTunnel

@Suite("TunnelAddressClassifier")
struct TunnelAddressClassifierTests {
    @Test func ipv6ULAClassifierParsesLiteralsAndRejectsHostnames() {
        // proto/pairing.md:95 pins the IPv6 ULA range definition, not end-to-end scan-time refusal.
        // ULA classification must parse IPv6 literals, not string prefixes.
        let cases: [(host: String, expected: Bool)] = [
            ("fd12:3456::1", true),
            ("[fd00::1]", true),
            ("fd00::1%en0", true),
            ("[fd00::1%en0]", true),
            ("fc00::1", true),
            ("FD12:3456::1", true),
            ("fcheese.local", false),
            ("fd-something.lan", false),
            ("fe80::1", false),
            ("2001:db8::1", false),
            ("192.168.1.10", false),
            ("::ffff:192.168.1.10", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isIPv6ULA(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }

    @Test func rfc1918ClassifierCoversIPv4LiteralEdgeCasesOnly() {
        // proto/pairing.md:95 pins the IPv4 private range definitions, not end-to-end scan-time refusal.
        let cases: [(host: String, expected: Bool)] = [
            ("172.15.255.255", false),
            ("172.32.0.1", false),
            ("172.16.0.1", true),
            ("10.2.3.4", true),
            ("192.168.4.20", true),
            ("127.0.0.1", false),
            ("100.64.0.1", false),
            ("fd12:3456::1", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isRFC1918IPv4Literal(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }
}
