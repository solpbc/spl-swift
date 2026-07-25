// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// Ports reserved for fixed-port reclaim tests. OS-assigned (`.any`) binds draw
/// only from the macOS ephemeral range 49152-65535
/// (`net.inet.ip.portrange.first`/`.last`), so a listener on an explicit port
/// below 49152 cannot be stolen by a concurrent `.any` bind in another suite.
/// These constants must stay distinct because the suites run concurrently.
enum FixedPortReclaimTestPorts {
    // TunnelSupervisor reconnect reclaim site.
    static let tunnelSupervisorRebindPort = 39080

    // LoopbackProxy reconnect reclaim site.
    static let loopbackProxyRebindPort = 39081

    // Integration MockHome reconnect reclaim site.
    static let integrationMockHomeRebindPort = 39082
}
