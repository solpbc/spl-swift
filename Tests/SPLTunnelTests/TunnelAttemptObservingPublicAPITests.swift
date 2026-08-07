// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import SPLTunnel
import Testing

@Suite("Tunnel Attempt Observing Public API")
struct TunnelAttemptObservingPublicAPITests {
    @Test func packageVersionAdvancesForAttemptObservability() {
        #expect(SPLTunnelPackage.version == "0.3.2")
    }

    @Test func publicTypesAndConcreteSessionConformance() {
        let routes: [TunnelAttemptRoute] = [.directPinned, .directUnpinned, .relay]
        let failures: [TunnelAttemptFailureClass] = [
            .unreachable, .tls, .authRefreshRequired, .notEntitled, .revoked, .transport, .other,
        ]
        let phases: [TunnelAttemptPhase] = [
            .started,
            .waitingForBroker(elapsedMilliseconds: 1),
            .transportReady(elapsedMilliseconds: 2),
            .selected(elapsedMilliseconds: 3),
            .failed(.tls, elapsedMilliseconds: 4),
            .cancelled(elapsedMilliseconds: 5),
        ]
        let events = zip(routes, phases).enumerated().map { index, pair in
            TunnelAttemptEvent(route: pair.0, ordinal: index, phase: pair.1)
        }

        #expect(routes == [.directPinned, .directUnpinned, .relay])
        #expect(failures.count == 7)
        #expect(events[0] == TunnelAttemptEvent(route: .directPinned, ordinal: 0, phase: .started))

        let pairing = StoredPairing(
            instanceID: "instance",
            homeLabel: "home",
            relayEndpoint: "wss://relay.example/session",
            fingerprint: "fingerprint",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: .unavailable,
            pairedAt: Date(timeIntervalSince1970: 0)
        )
        let clientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")
        let session = TunnelSession(pairing: pairing, clientInfo: clientInfo)
        let erasedSession: any TunnelSessioning = session
        let supervisor = TunnelSupervisor(pairing: pairing, clientInfo: clientInfo)
        let erasedSupervisor: any TunnelSessioning = supervisor

        #expect((erasedSession as? any TunnelAttemptObserving) != nil)
        #expect((erasedSupervisor as? any TunnelAttemptObserving) == nil)
        _ = session.attemptUpdates
    }
}
