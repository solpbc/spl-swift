// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Supplies the client app identifier used for direct encrypted communication with the journal home server.
public struct SPLClientInfo: Sendable {
    public let userAgent: String
    /// The system the consuming app runs on, sent at pairing as the optional
    /// `platform` hint (proto/pairing.md §5). The journal names what this device
    /// sends it from the hint, and that name is never renamed, so it is a fixed
    /// value per app and never the owner-editable device label.
    public let platform: SPLPlatform?

    public init(userAgent: String, platform: SPLPlatform? = nil) {
        self.userAgent = userAgent
        self.platform = platform
    }
}

/// The `platform` pairing hint values the two consuming apps send.
public enum SPLPlatform: String, Sendable, Equatable {
    case macos
    case ios
}
