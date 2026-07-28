// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public struct KeepalivePolicy: Sendable, Equatable {
    public let interval: Duration
    public let missedLimit: Int
    public let runsOnRelayPath: Bool

    public init(
        interval: Duration = .milliseconds(500),
        missedLimit: Int = 3,
        // why: proto/framing.md:163-169 defines keepalive cadence as direct-mode dialer policy.
        runsOnRelayPath: Bool = false
    ) {
        self.interval = interval
        self.missedLimit = missedLimit
        self.runsOnRelayPath = runsOnRelayPath
    }
}

public struct RacePolicy: Sendable, Equatable {
    public let stagger: Duration
    public let loserGrace: Duration
    public let budget: Duration
    public let directConnectTimeout: Duration
    public let relayOpenTimeout: Duration
    public let heldRelayTimeout: Duration

    public init(
        stagger: Duration = .milliseconds(50),
        loserGrace: Duration = .milliseconds(250),
        budget: Duration = .seconds(8),
        directConnectTimeout: Duration = .seconds(5),
        relayOpenTimeout: Duration = .seconds(5),
        // why: proto/session.md:344 makes waiting-phase timeout client-owned, not relay-owned.
        heldRelayTimeout: Duration = .seconds(600)
    ) {
        self.stagger = stagger
        self.loserGrace = loserGrace
        self.budget = budget
        self.directConnectTimeout = directConnectTimeout
        self.relayOpenTimeout = relayOpenTimeout
        self.heldRelayTimeout = heldRelayTimeout
    }
}

public struct ProbeWatchdogPolicy: Sendable, Equatable {
    public let healthyInterval: Duration
    public let degradedInterval: Duration
    public let silentFailureLimit: Int
    public let activeInboundFailureLimit: Int
    public let forcedReconnectDegradedIntervalCap: Duration
    public let jitterRange: ClosedRange<Double>

    public init(
        healthyInterval: Duration,
        // why: deployed macOS probe watchdog degrades to 5 s after repeated failed probes.
        degradedInterval: Duration = .seconds(5),
        // why: deployed macOS probe watchdog forces reconnect after 3 silent failures.
        silentFailureLimit: Int = 3,
        // why: deployed macOS probe watchdog raises the limit to 6 when inbound activity advances.
        activeInboundFailureLimit: Int = 6,
        // why: deployed macOS probe watchdog caps forced-reconnect degraded cadence at 120 s.
        forcedReconnectDegradedIntervalCap: Duration = .seconds(120),
        // why: reconnect and probe policy jitter use the same 0.75...1.25 spread.
        jitterRange: ClosedRange<Double> = 0.75...1.25
    ) {
        self.healthyInterval = healthyInterval
        self.degradedInterval = degradedInterval
        self.silentFailureLimit = silentFailureLimit
        self.activeInboundFailureLimit = activeInboundFailureLimit
        self.forcedReconnectDegradedIntervalCap = forcedReconnectDegradedIntervalCap
        self.jitterRange = jitterRange
    }
}

public struct SessionPolicy: Sendable, Equatable {
    public let race: RacePolicy
    public let keepalive: KeepalivePolicy

    public init(
        race: RacePolicy = RacePolicy(),
        keepalive: KeepalivePolicy = KeepalivePolicy()
    ) {
        self.race = race
        self.keepalive = keepalive
    }
}
