// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
import SPLTunnel

@Suite("ReconnectBackoff Public API")
struct ReconnectBackoffPublicAPITests {
    @Test func publicSurfaceDrivesReconnectBackoff() {
        // proto/session.md:334 ("mobile reconnect — dial WS / tunnel WS") pins reconnect backoff: "Backoff is: 1 s, then 5 s, then 10 s, capped at 30 s, with the same ±25% jitter."
        let defaultTable = ReconnectBackoff.Schedule.defaultTable
        #expect(defaultTable == [.seconds(1), .seconds(5), .seconds(10), .seconds(30)])
        #expect(ReconnectBackoff.Schedule.default == .table(defaultTable))
        let jitterRange = ReconnectBackoff.defaultJitterRange
        #expect(jitterRange.lowerBound == 0.75)
        #expect(jitterRange.upperBound == 1.25)

        var lowerJitter = ReconnectBackoff(random: { $0.lowerBound })
        #expect(lowerJitter.nextDelay().delay == .milliseconds(750))

        var upperJitter = ReconnectBackoff(random: { $0.upperBound })
        #expect(upperJitter.nextDelay().delay == .milliseconds(1_250))

        var backoff = ReconnectBackoff(random: { _ in 1.0 })
        let steps = (0..<(defaultTable.count + 1)).map { _ in backoff.nextDelay() }
        #expect(steps.map(\.attempt) == Array(1...(defaultTable.count + 1)))
        #expect(steps.map(\.delay) == defaultTable + defaultTable.suffix(1))

        backoff.reset()
        let resetStep = backoff.nextDelay()
        #expect(resetStep.attempt == 1)
        #expect(resetStep.delay == defaultTable[0])

        var exponential = ReconnectBackoff(
            schedule: .exponential(initial: .seconds(2), multiplier: 2, cap: .seconds(10)),
            random: { _ in 1.0 }
        )
        let exponentialStep = exponential.nextDelay()
        #expect(exponentialStep.attempt == 1)
        #expect(exponentialStep.delay == .seconds(2))
    }
}
