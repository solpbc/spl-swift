// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network

enum TunnelAddressClassifier {
    static func isIPv6ULA(_ host: String) -> Bool {
        var normalized = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if normalized.hasPrefix("["), normalized.hasSuffix("]") {
            normalized.removeFirst()
            normalized.removeLast()
        }
        if let zoneIndex = normalized.firstIndex(of: "%") {
            normalized = String(normalized[..<zoneIndex])
        }
        guard let address = IPv6Address(normalized), let firstByte = address.rawValue.first else {
            return false
        }
        return firstByte & 0xfe == 0xfc
    }

    static func isRFC1918IPv4Literal(_ host: String) -> Bool {
        guard let octets = ipv4Octets(host) else {
            return false
        }
        switch (octets[0], octets[1]) {
        case (10, _), (172, 16...31), (192, 168):
            return true
        default:
            return false
        }
    }

    static func isIPv4LoopbackLiteral(_ host: String) -> Bool {
        guard let octets = ipv4Octets(host) else {
            return false
        }
        return octets[0] == 127
    }

    static func isIPv4LinkLocalLiteral(_ host: String) -> Bool {
        guard let octets = ipv4Octets(host) else {
            return false
        }
        return octets[0] == 169 && octets[1] == 254
    }

    static func isLocalNetworkAddressLiteral(_ host: String) -> Bool {
        isRFC1918IPv4Literal(host) ||
            isIPv4LoopbackLiteral(host) ||
            isIPv4LinkLocalLiteral(host) ||
            isIPv6ULA(host)
    }

    private static func ipv4Octets(_ host: String) -> [Int]? {
        // IPv4 literals require exactly four non-empty, in-range decimal octets.
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        let octets = parts.map { Int($0) }
        guard octets.allSatisfy({ $0 != nil }) else {
            return nil
        }
        let values = octets.compactMap(\.self)
        guard values.count == 4, values.allSatisfy({ 0...255 ~= $0 }) else {
            return nil
        }
        return values
    }
}
