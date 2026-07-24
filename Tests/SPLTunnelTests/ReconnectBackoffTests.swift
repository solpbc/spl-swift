// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
@testable import SPLTunnel

@Suite("ReconnectBackoff")
struct ReconnectBackoffTests {
    @Test func defaultTableFollowsProtoReconnectBackoff() {
        // session.md:325-336 pins mobile reconnect backoff at 1 s, 5 s, 10 s, capped 30 s.
        var backoff = ReconnectBackoff(random: { _ in 1.0 })
        let defaultTable = ReconnectBackoff.Schedule.defaultTable
        let steps = nextSteps(defaultTable.count + 1, from: &backoff)

        #expect(steps.map(\.delay) == defaultTable + [defaultTable.last!])
        #expect(steps.map(\.attempt) == Array(1...(defaultTable.count + 1)))
    }

    @Test func exponentialScheduleAppliesMultiplierAndCap() {
        var backoff = ReconnectBackoff(
            schedule: .exponential(initial: .seconds(2), multiplier: 2, cap: .seconds(10)),
            random: { _ in 1.0 }
        )

        #expect(nextSteps(5, from: &backoff).map(\.delay) == [
            .seconds(2),
            .seconds(4),
            .seconds(8),
            .seconds(10),
            .seconds(10),
        ])
    }

    @Test func resetRestartsAttemptAtOne() {
        // session.md:325-336 pins success and explicit reconnect redrives restarting at attempt 1.
        var backoff = ReconnectBackoff(random: { _ in 1.0 })

        _ = backoff.nextDelay()
        _ = backoff.nextDelay()
        backoff.reset()

        let step = backoff.nextDelay()
        #expect(step.attempt == 1)
        #expect(step.delay == ReconnectBackoff.Schedule.defaultTable[0])
    }

    @Test func jitterAppliesLowerUpperAndIdentityBounds() {
        var lower = ReconnectBackoff(random: { $0.lowerBound })
        #expect(lower.nextDelay().delay == .milliseconds(750))

        var upper = ReconnectBackoff(random: { $0.upperBound })
        #expect(upper.nextDelay().delay == .milliseconds(1_250))

        var identity = ReconnectBackoff(random: { _ in 1.0 })
        #expect(identity.nextDelay().delay == ReconnectBackoff.Schedule.defaultTable[0])
    }
}

private func nextSteps(_ count: Int, from backoff: inout ReconnectBackoff) -> [ReconnectBackoff.Step] {
    (0..<count).map { _ in backoff.nextDelay() }
}
