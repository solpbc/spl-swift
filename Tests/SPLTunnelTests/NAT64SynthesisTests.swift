// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Network
import Testing
@testable import SPLTunnel

@Suite("NAT64Synthesis")
struct NAT64SynthesisTests {
    // App Review tests on an IPv6-only network with NAT64. A direct pair link carries an IPv4
    // literal, and an `.ipv4` NWConnection endpoint is not synthesized there (measured 2026-09-25 on
    // a MacNAT64 network: NWError 50, network is down), so the dial must use getaddrinfo's answer.

    @Test func synthesizedIPv6AnswerWinsForAnIPv4Literal() throws {
        let synthesized = try #require(IPv6Address("64:ff9b::313:49b7"))
        let host = NAT64Synthesis.choose(literal: "3.19.73.183", from: [.ipv6(synthesized)])
        #expect(host == .ipv6(synthesized))
    }

    @Test func synthesizedIPv6AnswerWinsEvenBesideAnIPv4Answer() throws {
        // A MacNAT64 client also holds 192.0.0.2, so an IPv4 answer can appear beside the
        // synthesized one; only the IPv6 path routes.
        let synthesized = try #require(IPv6Address("2001:2:0:1baa::313:49b7"))
        let host = NAT64Synthesis.choose(literal: "3.19.73.183", from: [.ipv4, .ipv6(synthesized)])
        #expect(host == .ipv6(synthesized))
    }

    @Test func literalIsDialedUnchangedWithoutAnIPv6Answer() {
        #expect(NAT64Synthesis.choose(literal: "3.19.73.183", from: [.ipv4]) == NWEndpoint.Host("3.19.73.183"))
        #expect(NAT64Synthesis.choose(literal: "3.19.73.183", from: []) == NWEndpoint.Host("3.19.73.183"))
    }

    @Test func hostnamesAndIPv6LiteralsPassThrough() async {
        #expect(await NAT64Synthesis.dialHost("link.solstone.app", port: 443) == NWEndpoint.Host("link.solstone.app"))
        #expect(await NAT64Synthesis.dialHost("fd00::1", port: 7657) == NWEndpoint.Host("fd00::1"))
    }

    @Test func ipv4LiteralOnADualStackHostStaysIPv4() async {
        // The CI hosts are dual-stack with no NAT64, so getaddrinfo answers with the literal itself.
        #expect(await NAT64Synthesis.dialHost("127.0.0.1", port: 7657) == NWEndpoint.Host("127.0.0.1"))
    }
}
