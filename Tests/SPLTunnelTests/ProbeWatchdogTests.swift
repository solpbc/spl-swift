// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
@testable import SPLTunnel

@Suite("ProbeWatchdog")
struct ProbeWatchdogTests {
    @Test func forcedReconnectCadenceBacksOffAcrossReconnects() {
        var watchdog = makeWatchdog()

        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))

        #expect(failedProbe(&watchdog).nextInterval == .seconds(10))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(10))
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))

        #expect(failedProbe(&watchdog).nextInterval == .seconds(20))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(20))
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))
    }

    @Test func successResetsForcedReconnectCadence() {
        var watchdog = makeWatchdog()

        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))

        #expect(successfulProbe(&watchdog).nextInterval == .seconds(30))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        #expect(failedProbe(&watchdog).nextInterval == .seconds(5))
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))
    }

    @Test func forcedReconnectCounterSurvivesConnectionEstablished() {
        var watchdog = makeWatchdog()

        _ = failedProbe(&watchdog)
        _ = failedProbe(&watchdog)
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))

        watchdog.noteConnectionEstablished()

        #expect(failedProbe(&watchdog).nextInterval == .seconds(10))
    }

    @Test func everyFailedProbeCountsEvenWhenInboundAdvances() {
        var watchdog = makeWatchdog()

        for _ in 1...5 {
            let verdict = failedProbe(&watchdog, inboundAdvanced: true)
            #expect(verdict.action == .none)
        }

        assertReconnect(failedProbe(&watchdog, inboundAdvanced: true), nextInterval: .seconds(30))
    }

    @Test func inboundAdvanceRaisesLimitToSixAndEscalatesAtSix() {
        var watchdog = makeWatchdog()

        let first = failedProbe(&watchdog, inboundAdvanced: true)
        #expect(first.health == .unknown)
        #expect(first.action == .none)

        for _ in 2...5 {
            let verdict = failedProbe(&watchdog, inboundAdvanced: true)
            #expect(verdict.health == .degraded)
            #expect(verdict.action == .none)
        }

        assertReconnect(failedProbe(&watchdog, inboundAdvanced: true), nextInterval: .seconds(30))
    }

    @Test func activeTransferAcceleratesOnlyWithoutInboundDelta() {
        var stalled = makeWatchdog()

        let immediate = failedProbe(&stalled, inboundAdvanced: false, activeLocalTransfers: 1)
        #expect(immediate.health == .unknown)
        #expect(immediate.action == .reconnect)

        var advancing = makeWatchdog()
        for _ in 1...5 {
            let verdict = failedProbe(&advancing, inboundAdvanced: true, activeLocalTransfers: 1)
            #expect(verdict.action == .none)
        }
        assertReconnect(
            failedProbe(&advancing, inboundAdvanced: true, activeLocalTransfers: 1),
            nextInterval: .seconds(30)
        )
    }

    @Test func forcedReconnectDoesNotStormWhenReconnectNeverEstablishes() {
        var watchdog = makeWatchdog()

        _ = failedProbe(&watchdog)
        _ = failedProbe(&watchdog)
        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))

        let firstAfterForce = failedProbe(&watchdog)
        #expect(firstAfterForce.action == .none)
        #expect(firstAfterForce.nextInterval == .seconds(10))

        let secondAfterForce = failedProbe(&watchdog)
        #expect(secondAfterForce.action == .none)
        #expect(secondAfterForce.nextInterval == .seconds(10))

        assertReconnect(failedProbe(&watchdog), nextInterval: .seconds(30))
    }

    @Test func firstFailedProbeUsesDegradedInterval() {
        var watchdog = makeWatchdog()

        let verdict = failedProbe(&watchdog)

        #expect(verdict.health == .unknown)
        #expect(verdict.action == .none)
        #expect(verdict.nextInterval == .seconds(5))
    }

    @Test func jitterAppliesLowerUpperAndIdentityBounds() {
        var lower = makeWatchdog(random: { $0.lowerBound })
        #expect(successfulProbe(&lower).nextInterval == .milliseconds(22_500))

        var upper = makeWatchdog(random: { $0.upperBound })
        #expect(successfulProbe(&upper).nextInterval == .milliseconds(37_500))

        var identity = makeWatchdog(random: { _ in 1.0 })
        #expect(successfulProbe(&identity).nextInterval == .seconds(30))
    }
}

private func makeWatchdog(
    random: @escaping @Sendable (ClosedRange<Double>) -> Double = { _ in 1.0 }
) -> ProbeWatchdog {
    ProbeWatchdog(
        policy: ProbeWatchdogPolicy(healthyInterval: .seconds(30)),
        random: random
    )
}

private func successfulProbe(_ watchdog: inout ProbeWatchdog) -> ProbeWatchdogVerdict {
    watchdog.evaluate(probeSucceeded: true, inboundAdvanced: false, activeLocalTransfers: 0)
}

private func failedProbe(
    _ watchdog: inout ProbeWatchdog,
    inboundAdvanced: Bool = false,
    activeLocalTransfers: Int = 0
) -> ProbeWatchdogVerdict {
    watchdog.evaluate(
        probeSucceeded: false,
        inboundAdvanced: inboundAdvanced,
        activeLocalTransfers: activeLocalTransfers
    )
}

private func assertReconnect(_ verdict: ProbeWatchdogVerdict, nextInterval: Duration) {
    #expect(verdict.health == .degraded)
    #expect(verdict.action == .reconnect)
    #expect(verdict.nextInterval == nextInterval)
}
