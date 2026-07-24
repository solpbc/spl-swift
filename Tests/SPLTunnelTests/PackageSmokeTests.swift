// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing

@testable import SPLTunnel

@Suite struct PackageSmokeTests {
    @Test func packageVersionIsSet() {
        #expect(!SPLTunnelPackage.version.isEmpty)
    }
}
