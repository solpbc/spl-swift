// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// The candidate order `RaceCoordinator` actually races against. Exposed publicly so a caller
/// can map a `TunnelAttemptEvent.ordinal` back to the `TransportEndpoint` it refers to —
/// `TunnelAttemptEvent`'s ordinals are assigned against this sorted order, not the order
/// `endpoints` was passed in.
public enum CandidateOrdering {
    public static func sorted(
        _ endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint? = nil
    ) -> [TransportEndpoint] {
        endpoints.enumerated()
            .sorted { lhs, rhs in
                let leftPreferred = lhs.element == preferredEndpoint ? 0 : 1
                let rightPreferred = rhs.element == preferredEndpoint ? 0 : 1
                if leftPreferred != rightPreferred {
                    return leftPreferred < rightPreferred
                }
                let leftRank = rank(lhs.element)
                let rightRank = rank(rhs.element)
                if leftRank == rightRank {
                    return lhs.offset < rhs.offset
                }
                return leftRank < rightRank
            }
            .map(\.element)
    }

    static func rank(_ endpoint: TransportEndpoint) -> Int {
        switch endpoint {
        case .lan(let host, _, _, _):
            if TunnelAddressClassifier.isRFC1918IPv4Literal(host), !endpoint.unpinnedInterface {
                return 0
            }
            if TunnelAddressClassifier.isIPv6ULA(host) {
                return 1
            }
            if TunnelAddressClassifier.isRFC1918IPv4Literal(host), endpoint.unpinnedInterface {
                return 3
            }
            return 2
        case .relay:
            return 4
        }
    }
}
