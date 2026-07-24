// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Network
import Testing
@testable import SPLTunnel

@Suite("InnerTLS LAN parameters")
struct InnerTLSLANParameterTests {
    @Test func lanParametersPinOnlyRFC1918IPv4LiteralsToNonOtherInterfaces() {
        // Interface-type restrictions apply only to pinned RFC1918 IPv4 literals.
        let pinnedRFC1918 = InnerTLS.lanParametersForTesting(host: "192.168.1.10", unpinnedInterface: false)
        #expect(pinnedRFC1918.prohibitedInterfaceTypes == [.other])

        let unpinnedRFC1918 = InnerTLS.lanParametersForTesting(host: "192.168.1.10", unpinnedInterface: true)
        #expect(unpinnedRFC1918.prohibitedInterfaceTypes?.contains(.other) != true)

        for host in ["fd12:3456::1", "100.64.0.1", "203.0.113.10", "home.local"] {
            let parameters = InnerTLS.lanParametersForTesting(host: host, unpinnedInterface: false)
            #expect(parameters.prohibitedInterfaceTypes?.contains(.other) != true, "host \(host)")
        }
    }
}
