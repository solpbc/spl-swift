// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Describes the high-level attempt state of a tunnel supervisor.
///
/// Consumers can render idle, attempting, unavailable-between-generations, connected, and terminal
/// states directly without combining `stateUpdates` and `reconnectUpdates` or observing child sessions.
/// This state represents high-level supervisor attempt lifecycle rather than individual child TLS or broker phases.
/// Values carry no host, port, URL, token, certificate, or raw `SessionError` string payloads.
public enum TunnelSupervisorAttemptState: Sendable, Equatable, CustomStringConvertible {
    /// The supervisor is not actively attempting or maintaining a connection.
    case idle
    /// A connection attempt is in progress.
    case attempting
    /// The supervisor is temporarily unavailable while waiting to retry or replacing a generation.
    case unavailable(TunnelSupervisorUnavailability)
    /// A connection generation is established and usable.
    case connected
    /// A terminal failure occurred requiring user or application intervention.
    case terminal(TunnelAttemptFailureClass)

    public var description: String {
        switch self {
        case .idle:
            return "idle"
        case .attempting:
            return "attempting"
        case .unavailable(let unavailability):
            return "unavailable(\(unavailability))"
        case .connected:
            return "connected"
        case .terminal(let failureClass):
            return "terminal(\(failureClass))"
        }
    }
}

/// Details of temporary supervisor unavailability between connection generations.
public enum TunnelSupervisorUnavailability: Sendable, Equatable, CustomStringConvertible {
    /// Transient failure between generations. `retryAfter` is the `Duration` actually handed to the backoff sleeper.
    case retrying(failureClass: TunnelAttemptFailureClass, attempt: Int, retryAfter: Duration)
    /// Deliberate healthy-generation teardown before establishing a replacement generation. Has no failure class, attempt, or delay.
    case replacing

    public var description: String {
        switch self {
        case .retrying(let failureClass, let attempt, let retryAfter):
            return "retrying(failureClass: \(failureClass), attempt: \(attempt), retryAfter: \(retryAfter))"
        case .replacing:
            return "replacing"
        }
    }
}

extension SessionError {
    var attemptFailureClass: TunnelAttemptFailureClass {
        switch self {
        case .unreachable:
            .unreachable
        case .tlsFailed:
            .tls
        case .authRefreshRequired:
            .authRefreshRequired
        case .notEntitled:
            .notEntitled
        case .revoked:
            .revoked
        case .transportFailed, .inboundClosed, .directKeepaliveMissed, .relayKeepaliveMissed:
            .transport
        case .notConnected:
            .other
        }
    }
}
