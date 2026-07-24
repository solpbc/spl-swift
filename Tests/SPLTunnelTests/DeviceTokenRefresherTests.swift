// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let deviceTokenClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")
private let deviceTokenRelayHost = "refresh-relay.test"

@Suite("DeviceTokenRefresher", .serialized)
struct DeviceTokenRefresherTests {
    @Test func refresh401ExpiredIsDefinitiveAuthFailure() async {
        await expectRefreshResult(
            .http(status: 401, data: Data(#"{"reason":"expired"}"#.utf8)),
            expected: .definitiveAuthFailure
        )
    }

    @Test func refreshBare401IsTransient() async {
        await expectRefreshResult(.http(status: 401, data: Data()), expected: .transientFailure(pairing()))
    }

    @Test func refresh401OtherReasonIsTransient() async {
        await expectRefreshResult(
            .http(status: 401, data: Data(#"{"reason":"not expired"}"#.utf8)),
            expected: .transientFailure(pairing())
        )
    }

    @Test func refresh403InstanceRevokedIsDefinitiveAuthFailure() async {
        await expectRefreshResult(
            .http(status: 403, data: Data(#"{"error":"instance revoked"}"#.utf8)),
            expected: .definitiveAuthFailure
        )
    }

    @Test func refresh403UnrelatedIsTransient() async {
        await expectRefreshResult(
            .http(status: 403, data: Data(#"{"error":"temporarily blocked"}"#.utf8)),
            expected: .transientFailure(pairing())
        )
    }

    @Test func refresh404IsTransient() async {
        await expectRefreshResult(.http(status: 404, data: Data()), expected: .transientFailure(pairing()))
    }

    @Test func refresh5xxIsTransient() async {
        await expectRefreshResult(.http(status: 503, data: Data()), expected: .transientFailure(pairing()))
    }

    @Test func refreshNetworkErrorIsTransient() async {
        await expectRefreshResult(.failure(URLError(.notConnectedToInternet)), expected: .transientFailure(pairing()))
    }

    @Test func refreshDecodeFailureIsTransient() async {
        await expectRefreshResult(.http(status: 200, data: Data(#"{"not":"relay response"}"#.utf8)), expected: .transientFailure(pairing()))
    }

    @Test func refreshNonHTTPResponseIsTransient() async {
        await expectRefreshResult(.nonHTTP(data: Data()), expected: .transientFailure(pairing()))
    }

    @Test func refreshSuccessReturnsUpdatedPairingWithoutWritingKeychain() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { request in
            let body = try #require(request.httpBody)
            let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: String])
            #expect(request.url?.absoluteString == "https://\(deviceTokenRelayHost)/token/refresh")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
            #expect(request.value(forHTTPHeaderField: "User-Agent") == deviceTokenClientInfo.userAgent)
            #expect(json == ["device_token": "old-token"])
            return .http(status: 200, data: Data(#"{"device_token":"new-token","expires_at":"2036-01-01T00:00:00Z"}"#.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)

        let result = await refresher.refreshNow(pairing: pairing())

        #expect(result == .refreshed(pairing().updatingRelayEnrollment(.enrolled(
            deviceToken: "new-token",
            expiresAt: "2036-01-01T00:00:00Z"
        ))))
        let source = try String(contentsOf: Self.deviceTokenRefresherSourceURL(), encoding: .utf8)
        #expect(!source.contains("SPLKeychain"))
        #expect(!source.contains("SecItem"))
    }

    @Test func refreshUnavailableEnrollmentDoesNotCallRelay() async {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            Issue.record("relay should not be called")
            return .http(status: 500, data: Data())
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .unavailable)

        let result = await refresher.refreshNow(pairing: stored)

        #expect(result == .notNeeded(stored))
        #expect(HTTPStubProtocol.state.requests(forHost: deviceTokenRelayHost).isEmpty)
    }

    private func expectRefreshResult(_ stub: HTTPStubResult, expected: DeviceTokenRefreshResult) async {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in stub }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)

        let result = await refresher.refreshNow(pairing: pairing())

        #expect(result == expected)
    }

    private static func deviceTokenRefresherSourceURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/SPLTunnel/Pair/DeviceTokenRefresher.swift")
    }

    private func pairing(relayEnrollment: RelayEnrollment = .enrolled(deviceToken: "old-token", expiresAt: nil)) -> StoredPairing {
        StoredPairing(
            instanceID: "instance-1",
            homeLabel: "home",
            relayEndpoint: "https://\(deviceTokenRelayHost)",
            fingerprint: "sha256:\(String(repeating: "a", count: 64))",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: relayEnrollment,
            localEndpoints: [LocalEndpoint(host: "192.168.1.10", port: 7657, scope: "lan")],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }
}
