// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

public enum ProbeHealth: Sendable, Equatable {
    case unknown
    case healthy
    case degraded
}

public enum ProbeAction: Sendable, Equatable {
    case none
    case reconnect
}

public struct ProbeWatchdogVerdict: Sendable, Equatable {
    public let health: ProbeHealth
    public let action: ProbeAction
    public let nextInterval: Duration

    public init(health: ProbeHealth, action: ProbeAction, nextInterval: Duration) {
        self.health = health
        self.action = action
        self.nextInterval = nextInterval
    }
}

public struct ProbeWatchdog: Sendable {
    private let policy: ProbeWatchdogPolicy
    private let random: @Sendable (ClosedRange<Double>) -> Double
    private var consecutiveFailures = 0
    private var consecutiveForcedReconnects = 0

    public init(
        policy: ProbeWatchdogPolicy,
        random: @escaping @Sendable (ClosedRange<Double>) -> Double = { Double.random(in: $0) }
    ) {
        self.policy = policy
        self.random = random
    }

    public mutating func noteConnectionEstablished() {
        // why: the shipped macOS stopProbe bug reset forced reconnect backoff on every redial;
        // this transition resets probe failures only so E3 survives reconnect transitions.
        consecutiveFailures = 0
    }

    public mutating func evaluate(
        probeSucceeded: Bool,
        inboundAdvanced: Bool,
        activeLocalTransfers: Int
    ) -> ProbeWatchdogVerdict {
        if probeSucceeded {
            consecutiveFailures = 0
            consecutiveForcedReconnects = 0
            return ProbeWatchdogVerdict(
                health: .healthy,
                action: .none,
                nextInterval: jitteredDuration(
                    policy.healthyInterval,
                    range: policy.jitterRange,
                    random: random
                )
            )
        }

        consecutiveFailures += 1

        let activeTransferStalled = !inboundAdvanced && activeLocalTransfers > 0
        // Active local traffic with no inbound delta can only lower the effective threshold;
        // it never raises the threshold or delays reconnect escalation.
        let failureLimit = inboundAdvanced ? policy.activeInboundFailureLimit : policy.silentFailureLimit
        let shouldReconnect = activeTransferStalled || consecutiveFailures >= failureLimit
        let health: ProbeHealth = consecutiveFailures >= 2 ? .degraded : .unknown

        if shouldReconnect {
            consecutiveFailures = 0
            consecutiveForcedReconnects += 1
        }

        return ProbeWatchdogVerdict(
            health: health,
            action: shouldReconnect ? .reconnect : .none,
            nextInterval: intervalForFailedProbe()
        )
    }

    private func intervalForFailedProbe() -> Duration {
        if consecutiveFailures == 0 {
            return jitteredDuration(
                policy.healthyInterval,
                range: policy.jitterRange,
                random: random
            )
        }

        return jitteredDuration(
            degradedInterval(),
            range: policy.jitterRange,
            random: random
        )
    }

    private func degradedInterval() -> Duration {
        var interval = policy.degradedInterval
        for _ in 0..<consecutiveForcedReconnects {
            interval = minDuration(scaledDuration(interval, by: 2), policy.forcedReconnectDegradedIntervalCap)
        }
        return minDuration(interval, policy.forcedReconnectDegradedIntervalCap)
    }
}

func jitteredDuration(
    _ duration: Duration,
    range: ClosedRange<Double>,
    random: @Sendable (ClosedRange<Double>) -> Double
) -> Duration {
    scaledDuration(duration, by: random(range))
}

func scaledDuration(_ duration: Duration, by multiplier: Double) -> Duration {
    let components = duration.components
    let nanoseconds = Double(components.seconds) * 1_000_000_000
        + Double(components.attoseconds) / 1_000_000_000
    return .nanoseconds(Int64((nanoseconds * multiplier).rounded()))
}

func minDuration(_ lhs: Duration, _ rhs: Duration) -> Duration {
    lhs <= rhs ? lhs : rhs
}
