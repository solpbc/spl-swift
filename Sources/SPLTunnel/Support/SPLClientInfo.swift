// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Supplies the client app identifier used for direct encrypted communication with the journal home server.
public struct SPLClientInfo: Sendable {
    public let userAgent: String

    public init(userAgent: String) {
        self.userAgent = userAgent
    }
}
