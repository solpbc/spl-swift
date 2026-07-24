// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

public struct ReconnectBackoff: Sendable {
    public struct Step: Sendable, Equatable {
        public let attempt: Int
        public let delay: Duration
    }

    public enum Schedule: Sendable, Equatable {
        case table([Duration])
        case exponential(initial: Duration, multiplier: Double, cap: Duration)

        public static let defaultTable: [Duration] = [
            .seconds(1),
            .seconds(5),
            .seconds(10),
            .seconds(30),
        ]

        public static let `default`: Schedule = .table(defaultTable)

        func delay(forAttempt attempt: Int) -> Duration {
            let clampedAttempt = max(attempt, 1)
            switch self {
            case .table(let table):
                guard !table.isEmpty else {
                    return .seconds(0)
                }
                let index = min(clampedAttempt - 1, table.count - 1)
                return table[index]
            case .exponential(let initial, let multiplier, let cap):
                var delay = initial
                if clampedAttempt > 1 {
                    for _ in 2...clampedAttempt {
                        delay = minDuration(scaledDuration(delay, by: multiplier), cap)
                    }
                }
                return delay
            }
        }
    }

    public static let defaultJitterRange = 0.75...1.25

    private let schedule: Schedule
    private let jitterRange: ClosedRange<Double>
    private let random: @Sendable (ClosedRange<Double>) -> Double
    private var nextAttempt = 1

    public init(
        schedule: Schedule = .default,
        jitterRange: ClosedRange<Double> = defaultJitterRange,
        random: @escaping @Sendable (ClosedRange<Double>) -> Double = { Double.random(in: $0) }
    ) {
        self.schedule = schedule
        self.jitterRange = jitterRange
        self.random = random
    }

    public mutating func reset() {
        nextAttempt = 1
    }

    public mutating func nextDelay() -> Step {
        let attempt = nextAttempt
        nextAttempt += 1
        return Step(
            attempt: attempt,
            delay: jitteredDuration(
                schedule.delay(forAttempt: attempt),
                range: jitterRange,
                random: random
            )
        )
    }
}
