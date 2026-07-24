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
        let octets = host.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ 0...255 ~= $0 }) else {
            return false
        }
        switch (octets[0], octets[1]) {
        case (10, _), (172, 16...31), (192, 168):
            return true
        default:
            return false
        }
    }
}
