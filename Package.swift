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
        .library(name: "SPLTunnel", targets: ["SPLTunnel"]),
        .library(name: "SPLMark", targets: ["SPLMark"]),
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
        .target(
            name: "CArgon2",
            exclude: ["LICENSE", "README.md"],
            cSettings: [
                .define("ARGON2_NO_THREADS")
            ]
        ),
        .target(
            name: "SPLMark",
            dependencies: ["CArgon2"],
            exclude: ["NOTICE.md"],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SPLMarkTests",
            dependencies: [
                "SPLMark",
                "SPLTunnel",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            resources: [
                .copy("Vectors/mark-vectors.json")
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SPLTunnelTests",
            dependencies: ["SPLTunnel", "SPLMark"],
            resources: [
                .copy("Conformance/Corpus")
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
    ]
)
