// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let liveClientInfo = SPLClientInfo(userAgent: "spl-swift-live-tests/1")

@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["SPL_LIVE"] == "1"))
struct LiveStagingTests {
    static let deviceLabel = "spl-live-harness"

    @Test func dialStatusEndpoint() async throws {
        let config = try parseLiveEnv(ProcessInfo.processInfo.environment)
        let pairing = try await PairClient(clientInfo: liveClientInfo).pair(
            pairURL: config.pairURL,
            deviceLabel: Self.deviceLabel,
            relayEndpoint: config.relayEndpoint
        )
        let endpoints: [TransportEndpoint]
        if config.forceRelay {
            endpoints = try relayOnlyCandidates(for: pairing)
        } else {
            endpoints = TransportEndpoint.candidates(for: pairing)
        }

        let tunnel = TunnelSession(pairing: pairing, clientInfo: liveClientInfo)
        let via = try await tunnel.connect(endpoints: endpoints)

        do {
            let stream = try await tunnel.openStream()
            let request = "GET /app/network/api/status HTTP/1.1\r\nHost: \(pairing.homeLabel)\r\nConnection: close\r\n\r\n"
            try await stream.write(Data(request.utf8))
            try await stream.close()
            let response = try await Self.readResponse(from: stream.inbound)
            #expect(response.statusLine.contains("200"))
            guard let json = try JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
                Issue.record("Expected JSON response")
                return
            }
            guard json["posture"] != nil else {
                Issue.record("Expected posture field")
                return
            }

            if config.forceRelay {
                if case .relay = via {} else {
                    Issue.record("Expected relay transport when SPL_FORCE_RELAY=1")
                }
            }

            await tunnel.disconnect()
        } catch {
            await tunnel.disconnect()
            throw error
        }
    }

    private static func readResponse(from inbound: MuxInboundSequence) async throws -> (statusLine: String, body: Data) {
        var data = Data()
        for try await chunk in inbound {
            data.append(chunk)
        }
        guard let separator = data.range(of: Data("\r\n\r\n".utf8)),
              let headerText = String(data: data[..<separator.lowerBound], encoding: .utf8),
              let statusLine = headerText.components(separatedBy: "\r\n").first else {
            throw LiveStagingError.invalidResponse
        }
        return (statusLine, Data(data[separator.upperBound...]))
    }
}

private enum LiveStagingError: Error {
    case invalidResponse
}
