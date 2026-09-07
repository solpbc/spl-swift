// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let deviceTokenClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")
private let deviceTokenRelayHost = "refresh-relay.test"

@Suite("DeviceTokenRefresher", .serialized)
struct DeviceTokenRefresherTests {
    // proto/tokens.md:214-228 refresh verdicts distinguish definitive auth failures from transient failures.
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
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let newJWT = Self.v2JWT(instanceID: "instance-1", exp: 1_800_003_600)
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { request in
            let body = try #require(request.httpBody)
            let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
            #expect(request.url?.absoluteString == "https://\(deviceTokenRelayHost)/token/refresh")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
            #expect(request.value(forHTTPHeaderField: "User-Agent") == "spl")
            #expect(json["device_token"] as? String == "old-token")
            #expect(json["protocol_version"] as? Int == 2)
            return .http(status: 200, data: Data("""
            {"protocol_version":2,"device_token":"\(newJWT)","expires_at":"2027-01-15T09:00:00Z"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)

        let result = await refresher.refreshNow(pairing: pairing(), now: now)

        #expect(result == .refreshed(pairing().updatingRelayEnrollment(.enrolled(
            deviceToken: newJWT,
            expiresAt: "2027-01-15T09:00:00Z"
        ))))
        let source = try String(contentsOf: Self.deviceTokenRefresherSourceURL(), encoding: .utf8)
        #expect(!source.contains("SPLKeychain"))
        #expect(!source.contains("SecItem"))
    }

    @Test func refreshHoldingV2RejectsDowngradeToUnversionedV1() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let currentV2 = Self.v2JWT(instanceID: "instance-1", exp: 1_800_003_600)
        let legacyV1 = Self.legacyJWT(iat: 1_800_000_000, exp: 1_800_003_600)
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            .http(status: 200, data: Data("""
            {"device_token":"\(legacyV1)"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .enrolled(deviceToken: currentV2, expiresAt: nil))

        let result = await refresher.refreshNow(pairing: stored, now: now)

        #expect(result == .transientFailure(stored))
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

    @Test func refreshHoldingV1AcceptsUnversionedV1Response() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let oldV1 = Self.legacyJWT(iat: 1_799_000_000, exp: 1_800_001_000)
        let newV1 = Self.legacyJWT(iat: 1_800_000_000, exp: 1_800_003_600)
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            .http(status: 200, data: Data("""
            {"device_token":"\(newV1)","expires_at":"2027-01-15T09:00:00Z"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .enrolled(deviceToken: oldV1, expiresAt: nil))

        let result = await refresher.refreshNow(pairing: stored, now: now)

        #expect(result == .refreshed(stored.updatingRelayEnrollment(.enrolled(
            deviceToken: newV1,
            expiresAt: "2027-01-15T09:00:00Z"
        ))))
    }

    @Test func refreshV2RenewalWithNewJTIReplaces() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let oldV2 = Self.v2JWT(instanceID: "instance-1", exp: 1_800_001_000, jti: "jti-1")
        let newV2 = Self.v2JWT(instanceID: "instance-1", exp: 1_800_003_600, jti: "jti-2")
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            .http(status: 200, data: Data("""
            {"protocol_version":2,"device_token":"\(newV2)","expires_at":"2027-01-15T09:00:00Z"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .enrolled(deviceToken: oldV2, expiresAt: nil))

        let result = await refresher.refreshNow(pairing: stored, now: now)

        #expect(result == .refreshed(stored.updatingRelayEnrollment(.enrolled(
            deviceToken: newV2,
            expiresAt: "2027-01-15T09:00:00Z"
        ))))
    }

    @Test func refreshExpiredReplacementDoesNotReplacePriorState() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let currentV2 = Self.v2JWT(instanceID: "instance-1", exp: 1_800_001_000, jti: "jti-1")
        let expiredV2 = Self.v2JWT(instanceID: "instance-1", exp: 1_800_000_000, jti: "jti-expired") // exp == now -> expired
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            .http(status: 200, data: Data("""
            {"protocol_version":2,"device_token":"\(expiredV2)","expires_at":"2027-01-15T08:00:00Z"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .enrolled(deviceToken: currentV2, expiresAt: nil))

        let result = await refresher.refreshNow(pairing: stored, now: now)

        #expect(result == .transientFailure(stored))
    }

    @Test func refreshDiagnosticsNeverContainSecretSentinel() async throws {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let sentinel = "SECRET_TOKEN_SENTINEL"
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            .http(status: 200, data: Data("""
            {"protocol_version":2,"device_token":"\(sentinel)","expires_at":"bad-date"}
            """.utf8))
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing()

        let result = await refresher.refreshNow(pairing: stored, now: now)

        #expect(result == .transientFailure(stored))
        let debugDescription = String(describing: PairError.relayAccessInvalid)
        #expect(!debugDescription.contains(sentinel))
    }

    @Test func refreshIfNeededBeyondThirtyDayGraceDoesNotContactRelay() async {
        defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
        let token = Self.legacyJWT(iat: 1_000, exp: 2_000)
        let beyondGrace = Date(timeIntervalSince1970: 2_000 + 30 * 86_400 + 1)
        let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
            Issue.record("relay must not be called when token is beyond 30-day grace")
            return .http(status: 500, data: Data())
        }
        let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
        let stored = pairing(relayEnrollment: .enrolled(deviceToken: token, expiresAt: nil))

        let result = await refresher.refreshIfNeeded(pairing: stored, now: beyondGrace)

        #expect(result == .notNeeded(stored))
        #expect(HTTPStubProtocol.state.requests(forHost: deviceTokenRelayHost).isEmpty)
    }

    @Test func refreshPlaintextRelayEndpointDoesNotCallRelay() async {
        for relayEndpoint in ["http://\(deviceTokenRelayHost)", "ws://\(deviceTokenRelayHost)"] {
            defer { HTTPStubProtocol.state.reset(host: deviceTokenRelayHost) }
            let session = makeHTTPStubSession(host: deviceTokenRelayHost) { _ in
                Issue.record("relay should not be called")
                return .http(status: 500, data: Data())
            }
            let refresher = DeviceTokenRefresher(session: session, clientInfo: deviceTokenClientInfo)
            let stored = pairing(relayEndpoint: relayEndpoint)

            let result = await refresher.refreshNow(pairing: stored)

            #expect(result == .transientFailure(stored))
            #expect(HTTPStubProtocol.state.requests(forHost: deviceTokenRelayHost).isEmpty)
        }
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

    private func pairing(
        relayEndpoint: String = "https://\(deviceTokenRelayHost)",
        relayEnrollment: RelayEnrollment = .enrolled(deviceToken: "old-token", expiresAt: nil)
    ) -> StoredPairing {
        StoredPairing(
            instanceID: "instance-1",
            homeLabel: "home",
            relayEndpoint: relayEndpoint,
            fingerprint: "sha256:\(String(repeating: "a", count: 64))",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: relayEnrollment,
            localEndpoints: [LocalEndpoint(host: "192.168.1.10", port: 7657, scope: "lan")],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }

    private static func v2JWT(instanceID: String, exp: Int, jti: String = "jti-refresh") -> String {
        let payload: [String: Any] = [
            "iss": "solstone-relay",
            "sub": "instance:\(instanceID)",
            "aud": "spl-relay",
            "scope": "session.dial",
            "ver": 2,
            "instance_id": instanceID,
            "iat": exp - 3600,
            "exp": exp,
            "jti": jti,
        ]
        let data = try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(b64).sig"
    }

    private static func legacyJWT(iat: Int, exp: Int) -> String {
        let payload: [String: Any] = [
            "iat": Double(iat),
            "exp": Double(exp),
        ]
        let data = try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(b64).sig"
    }
}
