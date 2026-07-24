// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
@testable import SPLTunnel

enum FakeLANPairError: Error, Equatable, Sendable {
    case unreachable
    case missingOutcome
}

enum FakeLANOutcome: Sendable {
    case response(status: Int, body: Data)
    case error(any Error & Sendable)
}

struct FakeLANRequest: Sendable, Equatable {
    let host: String
    let port: Int
    let caFingerprintBytes: [UInt8]
    let requestBytes: Data
}

actor FakeLANPairTransport: LANPairTransport {
    private var outcomes: [FakeLANOutcome]
    private(set) var requests: [FakeLANRequest] = []

    init(outcomes: [FakeLANOutcome]) {
        self.outcomes = outcomes
    }

    var requestCount: Int {
        requests.count
    }

    func send(
        host: String,
        port: Int,
        caFingerprintBytes: [UInt8],
        requestBytes: Data
    ) async throws -> (status: Int, body: Data) {
        requests.append(FakeLANRequest(
            host: host,
            port: port,
            caFingerprintBytes: caFingerprintBytes,
            requestBytes: requestBytes
        ))
        guard !outcomes.isEmpty else {
            throw FakeLANPairError.missingOutcome
        }
        let outcome = outcomes.removeFirst()
        switch outcome {
        case .response(let status, let body):
            return (status, body)
        case .error(let error):
            throw error
        }
    }
}
