// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

struct RelayEndpoint: Sendable, Equatable {
    let url: URL

    init(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(),
              Self.secureSchemes.contains(scheme),
              url.host != nil else {
            throw RelayEndpointError.invalid
        }
        self.url = url
    }

    // why: this exists solely for test harnesses that target plaintext mocks and is unreachable from public API.
    static func unchecked(_ url: URL) -> RelayEndpoint {
        RelayEndpoint(url: url)
    }

    var webSocketScheme: String? {
        switch url.scheme?.lowercased() {
        case "https":
            "wss"
        case "wss":
            "wss"
        case "http":
            "ws"
        case "ws":
            "ws"
        default:
            nil
        }
    }

    var controlScheme: String? {
        switch url.scheme?.lowercased() {
        case "https":
            "https"
        case "wss":
            "https"
        case "http":
            "http"
        case "ws":
            "http"
        default:
            nil
        }
    }

    private init(url: URL) {
        self.url = url
    }

    private static let secureSchemes: Set<String> = ["https", "wss"]
}

enum RelayEndpointError: Error, Equatable, Sendable {
    case invalid
}
