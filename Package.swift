// swift-tools-version: 6.2
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import PackageDescription

let package = Package(
    name: "spl-swift",
    platforms: [
        .macOS(.v15),
        .iOS(.v26),
    ],
    products: [
        .library(name: "SPLTunnel", targets: ["SPLTunnel"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "SPLTunnel",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SPLTunnelTests",
            dependencies: ["SPLTunnel"],
            resources: [
                .copy("Conformance/Corpus")
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
    ]
)
