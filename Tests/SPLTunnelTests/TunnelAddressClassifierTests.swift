// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
@testable import SPLTunnel

@Suite("TunnelAddressClassifier")
struct TunnelAddressClassifierTests {
    @Test func ipv6ULAClassifierParsesLiteralsAndRejectsHostnames() {
        // proto/pairing.md:117 pins the IPv6 ULA range used by local direct-candidate refusal.
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
        // proto/pairing.md:117 pins the IPv4 private range definitions used by local direct-candidate refusal.
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

    @Test func rfc6598ClassifierCoversSharedAddressSpaceLiteralEdgesOnly() {
        // proto/pairing.md:117 explicitly admits RFC 6598 shared address space 100.64.0.0/10.
        let cases: [(host: String, expected: Bool)] = [
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.64.0.1", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("100.64.0", false),
            ("100.64.0.1.extra", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isRFC6598IPv4Literal(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }

    @Test func ipv4LoopbackClassifierCovers127Slash8Only() {
        let cases: [(host: String, expected: Bool)] = [
            ("127.0.0.1", true),
            ("127.255.255.255", true),
            ("126.255.255.255", false),
            ("128.0.0.1", false),
            ("127.0.0", false),
            ("127.0.0.1.extra", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isIPv4LoopbackLiteral(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }

    @Test func ipv4LinkLocalClassifierCovers169254Slash16Only() {
        let cases: [(host: String, expected: Bool)] = [
            ("169.254.0.1", true),
            ("169.254.255.255", true),
            ("169.253.255.255", false),
            ("169.255.0.1", false),
            ("169.254.0", false),
            ("169.254.0.1.extra", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isIPv4LinkLocalLiteral(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }

    @Test func localNetworkAddressCompositeCoversPairingLocalRanges() {
        // proto/pairing.md:117 direct candidate refusal accepts the explicit local/shared allow-list and rejects non-local literals.
        let cases: [(host: String, expected: Bool)] = [
            ("10.2.3.4", true),
            ("172.16.0.1", true),
            ("192.168.4.20", true),
            ("100.64.0.1", true),
            ("127.0.0.1", true),
            ("169.254.1.10", true),
            ("fd12:3456::1", true),
            ("[fd00::1]", true),
            ("192.0.2.10", false),
            ("198.51.100.20", false),
            ("100.128.0.0", false),
            ("fe80::1", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(
                TunnelAddressClassifier.isLocalNetworkAddressLiteral(testCase.host) == testCase.expected,
                "host \(testCase.host)"
            )
        }
    }

    @Test func malformedIPv4LiteralsAreNotLocalNetworkAddresses() {
        let cases = [
            "10.0.0.1.",
            "10..0.0.1",
            "10.0.0",
            "10.0.0.1.2",
            "10.0.0.256",
        ]

        for host in cases {
            #expect(
                TunnelAddressClassifier.isLocalNetworkAddressLiteral(host) == false,
                "host \(host)"
            )
        }
    }
}
