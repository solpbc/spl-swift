// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public enum RelayOrigin: Sendable, Equatable, Hashable {
    case wellKnown
    case custom(URL)

    public static let wellKnownDefault = URL(string: "https://link.solstone.app")!

    public func resolved(default origin: URL = RelayOrigin.wellKnownDefault) -> URL {
        switch self {
        case .wellKnown:
            origin
        case .custom(let url):
            url
        }
    }
}
