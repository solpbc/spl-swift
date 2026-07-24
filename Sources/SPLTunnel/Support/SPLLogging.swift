// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import os

enum SPLLogCategory: String, Sendable, CaseIterable {
    case dial
    case mux
    case tls
    case session
    case race
    case loopback
    case pair
    case deviceToken = "device-token"
    case transport
}

// This is the package's only shared mutable state: process-wide log policy is
// selected once at app launch, while all runtime state stays actor-owned.
public enum SPLLogging {
    private static let defaultSubsystem = "app.solstone.observer.spl"
    private static let stateLock = OSAllocatedUnfairLock(
        initialState: State(subsystem: defaultSubsystem, frozen: false)
    )

    /// Configures the process-wide SPL logging subsystem. First write wins:
    /// the subsystem freezes on the first configure call or first logger vend,
    /// and later configure calls are silent no-ops.
    public static func configure(subsystem: String) {
        stateLock.withLock { state in
            guard !state.frozen else {
                return
            }
            state.subsystem = subsystem
            state.frozen = true
        }
    }

    static func logger(for category: SPLLogCategory) -> Logger {
        let subsystem = stateLock.withLock { state in
            if !state.frozen {
                state.frozen = true
            }
            return state.subsystem
        }
        return Logger(subsystem: subsystem, category: category.rawValue)
    }

    private struct State {
        var subsystem: String
        var frozen: Bool
    }
}
