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

enum FakeLANPrepareOutcome: Sendable {
    case attempt(FakeLANOutcome)
    case error(any Error & Sendable)
}

struct FakeLANPrepare: Sendable, Equatable {
    let host: String
    let port: Int
    let caFingerprintBytes: [UInt8]
}

struct FakeLANRequest: Sendable, Equatable {
    let host: String
    let port: Int
    let caFingerprintBytes: [UInt8]
    let requestBytes: Data
}

actor FakeLANPairTransport: LANPairTransport {
    private var prepareOutcomes: [FakeLANPrepareOutcome]
    private let recorder = FakeLANRecorder()

    init(outcomes: [FakeLANOutcome]) {
        self.prepareOutcomes = outcomes.map { .attempt($0) }
    }

    init(prepareOutcomes: [FakeLANPrepareOutcome]) {
        self.prepareOutcomes = prepareOutcomes
    }

    var prepares: [FakeLANPrepare] {
        get async {
            await recorder.prepares
        }
    }

    var requests: [FakeLANRequest] {
        get async {
            await recorder.requests
        }
    }

    var requestCount: Int {
        get async {
            await recorder.requestCount
        }
    }

    var closeCount: Int {
        get async {
            await recorder.closeCount
        }
    }

    func prepare(
        host: String,
        port: Int,
        caFingerprintBytes: [UInt8]
    ) async throws -> any LANPairAttempt {
        let prepare = FakeLANPrepare(
            host: host,
            port: port,
            caFingerprintBytes: caFingerprintBytes
        )
        await recorder.recordPrepare(prepare)
        guard !prepareOutcomes.isEmpty else {
            throw FakeLANPairError.missingOutcome
        }
        let outcome = prepareOutcomes.removeFirst()
        switch outcome {
        case .error(let error):
            throw error
        case .attempt(let sendOutcome):
            return FakeLANPairAttempt(prepare: prepare, outcome: sendOutcome, recorder: recorder)
        }
    }
}

private actor FakeLANPairAttempt: LANPairAttempt {
    private let prepare: FakeLANPrepare
    private let outcome: FakeLANOutcome
    private let recorder: FakeLANRecorder
    private var closed = false

    init(prepare: FakeLANPrepare, outcome: FakeLANOutcome, recorder: FakeLANRecorder) {
        self.prepare = prepare
        self.outcome = outcome
        self.recorder = recorder
    }

    func send(requestBytes: Data) async throws -> (status: Int, body: Data) {
        await recorder.recordRequest(FakeLANRequest(
            host: prepare.host,
            port: prepare.port,
            caFingerprintBytes: prepare.caFingerprintBytes,
            requestBytes: requestBytes
        ))
        switch outcome {
        case .response(let status, let body):
            return (status, body)
        case .error(let error):
            throw error
        }
    }

    func close() async {
        guard !closed else {
            return
        }
        closed = true
        await recorder.recordClose()
    }
}

private actor FakeLANRecorder {
    private(set) var prepares: [FakeLANPrepare] = []
    private(set) var requests: [FakeLANRequest] = []
    private var recordedCloseCount = 0

    var requestCount: Int {
        requests.count
    }

    var closeCount: Int {
        recordedCloseCount
    }

    func recordPrepare(_ prepare: FakeLANPrepare) {
        prepares.append(prepare)
    }

    func recordRequest(_ request: FakeLANRequest) {
        requests.append(request)
    }

    func recordClose() {
        recordedCloseCount += 1
    }
}
