// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("DialPlanner")
struct DialPlannerTests {
    @Test func trustDirectPinsOnlyWithinWindowAndCurrentCandidates() {
        var planner = DialPlanner()
        let now = ContinuousClock.now
        let trusted = direct("10.0.0.5")
        let other = direct("203.0.113.10")
        let relay = relayEndpoint()

        planner.noteConnected(endpoint: trusted, now: now)

        let pinned = planner.plan(candidates: [other, trusted, relay], now: now.advanced(by: .seconds(4)))
        #expect(pinned.candidates == [other, trusted, relay])
        #expect(pinned.preferredEndpoint == trusted)

        let expired = planner.plan(candidates: [other, trusted, relay], now: now.advanced(by: .seconds(5)))
        #expect(expired.candidates == [other, trusted, relay])
        #expect(expired.preferredEndpoint == nil)

        planner.noteConnected(endpoint: trusted, now: now)
        let absent = planner.plan(candidates: [other, relay], now: now.advanced(by: .seconds(1)))
        #expect(absent.candidates == [other, relay])
        #expect(absent.preferredEndpoint == nil)

        let dropped = planner.plan(candidates: [trusted, other, relay], now: now.advanced(by: .seconds(2)))
        #expect(dropped.preferredEndpoint == nil)
    }

    @Test func relaySuccessTrustedFailureAndTerminalPauseClearTrustDirect() {
        var planner = DialPlanner()
        let now = ContinuousClock.now
        let trusted = direct("10.0.0.5")
        let relay = relayEndpoint()

        planner.noteConnected(endpoint: trusted, now: now)
        planner.noteConnected(endpoint: relay, now: now)
        #expect(planner.plan(candidates: [trusted, relay], now: now).preferredEndpoint == nil)

        planner.noteConnected(endpoint: trusted, now: now)
        let pinned = planner.plan(candidates: [trusted, relay], now: now)
        planner.noteFailure(.unreachable, attemptedTrustedEndpoint: pinned.preferredEndpoint)
        #expect(planner.plan(candidates: [trusted, relay], now: now).preferredEndpoint == nil)

        planner.noteConnected(endpoint: trusted, now: now)
        planner.noteTerminalPause()
        #expect(planner.plan(candidates: [trusted, relay], now: now).preferredEndpoint == nil)
    }

    @Test func directKeepaliveMissUsesRelayOnlyForExactlyOneCycle() {
        var planner = DialPlanner()
        let now = ContinuousClock.now
        let direct = direct("10.0.0.5")
        let relay = relayEndpoint()

        planner.noteConnected(endpoint: direct, now: now)
        planner.noteFailure(.directKeepaliveMissed, attemptedTrustedEndpoint: nil)

        let relayOnly = planner.plan(candidates: [direct, relay], now: now)
        #expect(relayOnly.candidates == [relay])
        #expect(relayOnly.preferredEndpoint == nil)

        let fullAgain = planner.plan(candidates: [direct, relay], now: now)
        #expect(fullAgain.candidates == [direct, relay])
        #expect(fullAgain.preferredEndpoint == nil)
    }

    @Test func relayOnlyCycleFallsBackToFullSetWhenNoRelayCandidateExists() {
        var planner = DialPlanner()
        let now = ContinuousClock.now
        let direct = direct("10.0.0.5")

        planner.noteFailure(.directKeepaliveMissed, attemptedTrustedEndpoint: nil)

        let fallback = planner.plan(candidates: [direct], now: now)
        #expect(fallback.candidates == [direct])
        #expect(fallback.preferredEndpoint == nil)

        let consumed = planner.plan(candidates: [direct], now: now)
        #expect(consumed.candidates == [direct])
        #expect(consumed.preferredEndpoint == nil)
    }
}

private func direct(_ host: String) -> TransportEndpoint {
    .lan(host: host, port: 443, scope: "test")
}
