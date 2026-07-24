// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Supplies the per-app User-Agent ("solstone-macos/<v>" / "solstone-ios/<v>") used by dial and pair requests.
public struct SPLClientInfo: Sendable {
    public let userAgent: String

    public init(userAgent: String) {
        self.userAgent = userAgent
    }
}
