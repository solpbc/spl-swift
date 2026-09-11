// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
import SPLTunnel

@Suite("TunnelSupervisorAttemptState Public API")
struct TunnelSupervisorAttemptStatePublicAPITests {
    @Test("Public enum cases and CustomStringConvertible output")
    func enumCasesAndDescriptions() {
        let idle: TunnelSupervisorAttemptState = .idle
        let attempting: TunnelSupervisorAttemptState = .attempting
        let retrying: TunnelSupervisorAttemptState = .unavailable(.retrying(failureClass: .transport, attempt: 2, retryAfter: .seconds(3)))
        let replacing: TunnelSupervisorAttemptState = .unavailable(.replacing)
        let connected: TunnelSupervisorAttemptState = .connected
        let terminal: TunnelSupervisorAttemptState = .terminal(.revoked)

        #expect(idle.description == "idle")
        #expect(attempting.description == "attempting")
        #expect(retrying.description == "unavailable(retrying(failureClass: transport, attempt: 2, retryAfter: 3.0 seconds))")
        #expect(replacing.description == "unavailable(replacing)")
        #expect(connected.description == "connected")
        #expect(terminal.description == "terminal(revoked)")

        let unavailabilityRetrying: TunnelSupervisorUnavailability = .retrying(failureClass: .tls, attempt: 1, retryAfter: .seconds(1))
        let unavailabilityReplacing: TunnelSupervisorUnavailability = .replacing
        #expect(unavailabilityRetrying.description == "retrying(failureClass: tls, attempt: 1, retryAfter: 1.0 seconds)")
        #expect(unavailabilityReplacing.description == "replacing")
    }

    @Test("TunnelSupervisor public attemptState and attemptStateUpdates method compile without testable import")
    func supervisorPublicInterface() async {
        let pairing = StoredPairing(
            instanceID: "instance",
            homeLabel: "home",
            relayEndpoint: "wss://relay.example/session",
            fingerprint: "fingerprint",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
            pairedAt: Date(timeIntervalSince1970: 0)
        )
        let supervisor = TunnelSupervisor(
            pairing: pairing,
            clientInfo: SPLClientInfo(userAgent: "public-api-test/1")
        )

        let erasedSupervisor: any TunnelSessioning = supervisor
        #expect((erasedSupervisor as? any TunnelAttemptObserving) == nil)

        let initial = await supervisor.attemptState
        #expect(initial == .idle)

        let stream1 = await supervisor.attemptStateUpdates()
        let stream2 = await supervisor.attemptStateUpdates()

        var iterator1 = stream1.makeAsyncIterator()
        let first1 = await iterator1.next()
        #expect(first1 == .idle)

        var iterator2 = stream2.makeAsyncIterator()
        let first2 = await iterator2.next()
        #expect(first2 == .idle)
    }
}
