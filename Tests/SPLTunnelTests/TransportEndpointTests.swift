// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("TransportEndpoint")
struct TransportEndpointTests {
    @Test func candidatesAddUnpinnedRFC1918DuplicateAsLastResortBeforeRelay() {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let pinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let ula = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let unpinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true)
        let pairing = pairing(
            relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
            localEndpoints: [
                LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
                LocalEndpoint(host: "fd12:3456::1", port: 443, scope: "ula"),
            ]
        )

        let candidates = TransportEndpoint.candidates(for: pairing)

        #expect(candidates == [pinned, unpinned, ula, relay])
    }

    @Test func directOnlyRFC1918CandidateKeepsUnpinnedFallbackPath() {
        let pinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let unpinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true)
        let pairing = pairing(
            relayEnrollment: .unavailable,
            localEndpoints: [
                LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
            ]
        )

        #expect(TransportEndpoint.candidates(for: pairing) == [pinned, unpinned])
    }

    @Test func candidatesKeepDirectWhenRelayMetadataIsAbsentBlankOrMalformed() {
        // candidates(for:) remains non-throwing and direct-preserving when relay metadata is absent or invalid.
        let localEndpoints = [
            LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
            LocalEndpoint(host: "fd12:3456::1", port: 443, scope: "ula"),
        ]
        let expectedDirect = [
            TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local"),
            TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true),
            TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula"),
        ]
        let variants: [StoredPairing] = [
            pairing(relayEnrollment: .unavailable, localEndpoints: localEndpoints),
            pairing(
                relayEnrollment: .enrolled(deviceToken: "   ", expiresAt: nil),
                localEndpoints: localEndpoints
            ),
            pairing(
                relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
                localEndpoints: localEndpoints,
                relayEndpoint: "://not-a-url"
            ),
            pairing(
                relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
                localEndpoints: localEndpoints,
                relayEndpoint: ""
            ),
        ]

        for variant in variants {
            #expect(TransportEndpoint.candidates(for: variant) == expectedDirect)
        }
    }

    @Test func connectedViaDropsRelaySecrets() {
        #expect(
            TransportEndpoint.lan(
                host: "192.168.1.10",
                port: 443,
                scope: "local",
                unpinnedInterface: true
            ).connectedVia == .lanDirect(host: "192.168.1.10", port: 443)
        )
        #expect(
            TransportEndpoint.relay(
                endpoint: URL(string: "wss://relay.example/session")!,
                instanceID: "secret-instance",
                deviceToken: "secret-token"
            ).connectedVia == .relay(endpoint: URL(string: "wss://relay.example/session")!)
        )
    }

    private func pairing(
        relayEnrollment: RelayEnrollment,
        localEndpoints: [LocalEndpoint],
        relayEndpoint: String = "wss://relay.example/session"
    ) -> StoredPairing {
        StoredPairing(
            instanceID: "instance",
            homeLabel: "home",
            relayEndpoint: relayEndpoint,
            fingerprint: "fingerprint",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: relayEnrollment,
            localEndpoints: localEndpoints,
            pairedAt: Date()
        )
    }
}
