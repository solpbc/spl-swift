// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Identifies a candidate's sanitized transport route without exposing endpoint identity.
public enum TunnelAttemptRoute: Sendable, Equatable {
    case directPinned
    case directUnpinned
    case relay
}

/// Classifies a candidate failure into a coarse, sanitized outcome.
public enum TunnelAttemptFailureClass: Sendable, Equatable {
    case unreachable
    case tls
    case authRefreshRequired
    case notEntitled
    case revoked
    case transport
    case other
}

/// Describes a candidate lifecycle transition. `started` establishes that candidate's time origin;
/// every other phase measures `elapsedMilliseconds` from it with the injected monotonic clock,
/// never wall time. Per-attempt causal order is exact, but concurrent candidates have no global
/// ordering guarantee.
public enum TunnelAttemptPhase: Sendable, Equatable {
    case started
    case waitingForBroker(elapsedMilliseconds: Int)
    case transportReady(elapsedMilliseconds: Int)
    case selected(elapsedMilliseconds: Int)
    case failed(TunnelAttemptFailureClass, elapsedMilliseconds: Int)
    case cancelled(elapsedMilliseconds: Int)
}

/// A sanitized candidate-observability event. It carries no host, port, scope, relay URL or origin,
/// instance ID, device token, certificate text, or upstream error string; failure detail is reduced
/// to a coarse class and all string payloads from `SessionError` are dropped.
public struct TunnelAttemptEvent: Sendable, Equatable {
    /// The candidate's sanitized route classification.
    public let route: TunnelAttemptRoute
    /// The stable zero-based index in sorted candidate order. Preferred promotion is visible only
    /// through this value, and byte-identical duplicates are distinguished only by this value.
    public let ordinal: Int
    /// The candidate lifecycle transition.
    public let phase: TunnelAttemptPhase

    /// Creates a sanitized candidate-observability event.
    public init(route: TunnelAttemptRoute, ordinal: Int, phase: TunnelAttemptPhase) {
        self.route = route
        self.ordinal = ordinal
        self.phase = phase
    }
}

/// Exposes sanitized candidate-observability events for a concrete tunnel session.
public protocol TunnelAttemptObserving: Sendable {
    /// A stream of events carrying no host, port, scope, relay URL or origin, instance ID, device
    /// token, certificate text, or upstream error string; failure detail is reduced to a coarse
    /// class and all string payloads from `SessionError` are dropped. A race retains at most
    /// `4 × candidateCount` values. The stream exists before `connect`, never waits for a subscriber,
    /// and finishes when the race resolves through selection, all-failure, or cancellation rather
    /// than at `disconnect()`.
    nonisolated var attemptUpdates: AsyncStream<TunnelAttemptEvent> { get }
}
