// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Darwin
import Foundation
import Network

private let logger = SPLLogging.logger(for: .dial)

/// Chooses the host a direct dial actually connects to.
///
/// why: an `NWConnection` to an `.ipv4` endpoint is not synthesized on an IPv6-only network
/// with NAT64 (App Review's network is one): the dial fails at once with `ENETDOWN`.
/// `getaddrinfo` does synthesize an IPv4 literal on such a network (iOS 9.2 / macOS 10.11.2 and
/// later), so a literal is resolved through it and a synthesized IPv6 address, when one comes back,
/// is dialed instead. Anywhere IPv4 is reachable, `getaddrinfo` returns the literal's own address
/// and the dial is unchanged. Hostnames and IPv6 literals pass straight through.
enum NAT64Synthesis {
    enum ResolvedFamily: Equatable, Sendable {
        case ipv4
        case ipv6(IPv6Address)
    }

    static func dialHost(_ host: String, port: UInt16) async -> NWEndpoint.Host {
        guard IPv4Address(host) != nil else {
            return NWEndpoint.Host(host)
        }
        let resolved = await withCheckedContinuation { (continuation: CheckedContinuation<[ResolvedFamily], Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: resolve(host, port: port))
            }
        }
        let chosen = choose(literal: host, from: resolved)
        if case .ipv6 = chosen {
            logger.notice("nat64 synthesized an ipv6 address for an ipv4 literal")
        }
        return chosen
    }

    /// An IPv6 answer for an IPv4 literal can only come from NAT64 synthesis, so it wins; with no
    /// IPv6 answer the literal is dialed as given.
    static func choose(literal: String, from resolved: [ResolvedFamily]) -> NWEndpoint.Host {
        for family in resolved {
            if case .ipv6(let address) = family {
                return .ipv6(address)
            }
        }
        return NWEndpoint.Host(literal)
    }

    private static func resolve(_ host: String, port: UInt16) -> [ResolvedFamily] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_DEFAULT
        var head: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &head) == 0, let first = head else {
            return []
        }
        defer { freeaddrinfo(head) }

        var families: [ResolvedFamily] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor {
            if entry.pointee.ai_family == AF_INET {
                families.append(.ipv4)
            } else if entry.pointee.ai_family == AF_INET6, let address = entry.pointee.ai_addr {
                let bytes = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    withUnsafeBytes(of: sin6.pointee.sin6_addr) { Data($0) }
                }
                if let ipv6 = IPv6Address(bytes) {
                    families.append(.ipv6(ipv6))
                }
            }
            cursor = entry.pointee.ai_next
        }
        return families
    }
}
