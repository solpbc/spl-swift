// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Replaces the per-app hardcoded User-Agent ("solstone-macos/<v>" / "solstone-ios/<v>") that later Dial/Pair lodes consume.
public struct SPLClientInfo: Sendable {
    public let userAgent: String

    public init(userAgent: String) {
        self.userAgent = userAgent
    }
}
