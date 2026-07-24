// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

struct DialPlan: Sendable, Equatable {
    let candidates: [TransportEndpoint]
    let preferredEndpoint: TransportEndpoint?
}

struct DialPlanner: Sendable {
    private let trustWindow: Duration
    private var trustedDirectEndpoint: TransportEndpoint?
    private var trustExpiresAt: ContinuousClock.Instant?
    private var relayOnlyNextCycle = false

    init(trustWindow: Duration = .seconds(5)) {
        self.trustWindow = trustWindow
    }

    mutating func plan(
        candidates: [TransportEndpoint],
        now: ContinuousClock.Instant
    ) -> DialPlan {
        if relayOnlyNextCycle {
            relayOnlyNextCycle = false
            let relayCandidates = candidates.filter { !$0.isDirect }
            return DialPlan(
                candidates: relayCandidates.isEmpty ? candidates : relayCandidates,
                preferredEndpoint: nil
            )
        }

        guard let trustedDirectEndpoint, let trustExpiresAt else {
            return DialPlan(candidates: candidates, preferredEndpoint: nil)
        }

        guard now < trustExpiresAt, candidates.contains(trustedDirectEndpoint) else {
            clearTrustedDirect()
            return DialPlan(candidates: candidates, preferredEndpoint: nil)
        }

        return DialPlan(candidates: candidates, preferredEndpoint: trustedDirectEndpoint)
    }

    mutating func noteConnected(endpoint: TransportEndpoint?, now: ContinuousClock.Instant) {
        guard let endpoint, endpoint.isDirect else {
            clearTrustedDirect()
            return
        }
        trustedDirectEndpoint = endpoint
        trustExpiresAt = now.advanced(by: trustWindow)
    }

    mutating func noteFailure(_ error: SessionError, attemptedTrustedEndpoint: TransportEndpoint?) {
        if attemptedTrustedEndpoint != nil {
            clearTrustedDirect()
        }
        if error == .directKeepaliveMissed {
            clearTrustedDirect()
            relayOnlyNextCycle = true
        }
    }

    mutating func noteTerminalPause() {
        clearTrustedDirect()
        relayOnlyNextCycle = false
    }

    private mutating func clearTrustedDirect() {
        trustedDirectEndpoint = nil
        trustExpiresAt = nil
    }
}
