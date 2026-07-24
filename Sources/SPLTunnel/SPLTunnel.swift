// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// SPL (solstone private link) client library for Apple platforms.
///
/// This module implements the client side of the SPL protocol: pairing,
/// mutual-TLS tunnel establishment (direct LAN and relay), stream
/// multiplexing, and the local loopback proxy that carries application
/// HTTP over the tunnel.
///
/// The protocol specification lives in the `proto/` directory of
/// https://github.com/solpbc/spl and is the source of truth for all
/// wire behavior in this package.
public enum SPLTunnelPackage {
    /// The package version, set at release tagging.
    public static let version = "0.1.0-dev"
}
