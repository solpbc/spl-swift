// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("DeviceTokenClaims")
struct DeviceTokenClaimsTests {
    @Test func parseValidToken() throws {
        // proto/tokens.md:78-89 device-token claims include iat and exp seconds.
        let token = Self.token(payload: ["iat": 1_000.0, "exp": 2_000.0])

        let claims = try #require(DeviceTokenClaims.parse(token))

        #expect(claims.issuedAt == Date(timeIntervalSince1970: 1_000))
        #expect(claims.expiresAt == Date(timeIntervalSince1970: 2_000))
    }

    @Test func needsRefreshForMalformedShortMissingClaimsAndBadTTL() {
        // proto/tokens.md:78-99 malformed or incomplete token timing claims force refresh.
        #expect(DeviceTokenClaims.needsRefresh(token: nil, now: Date(timeIntervalSince1970: 1_500)))
        #expect(DeviceTokenClaims.needsRefresh(token: "not-a-jwt", now: Date(timeIntervalSince1970: 1_500)))
        #expect(DeviceTokenClaims.needsRefresh(token: Self.token(payload: ["iat": 1_000.0]), now: Date(timeIntervalSince1970: 1_500)))
        #expect(DeviceTokenClaims.needsRefresh(token: Self.token(payload: ["exp": 2_000.0]), now: Date(timeIntervalSince1970: 1_500)))
        #expect(DeviceTokenClaims.needsRefresh(token: Self.token(payload: ["iat": 2_000.0, "exp": 1_000.0]), now: Date(timeIntervalSince1970: 1_500)))
    }

    @Test func needsRefreshBoundaryUsesStrictlyGreaterThanEightyPercent() throws {
        let claims = try #require(DeviceTokenClaims.parse(Self.token(payload: ["iat": 1_000.0, "exp": 2_000.0])))

        // proto/tokens.md:98 pins refresh to strictly more than 80% of the TTL.
        #expect(!claims.needsRefresh(now: Date(timeIntervalSince1970: 1_799)))
        #expect(!claims.needsRefresh(now: Date(timeIntervalSince1970: 1_800)))
        #expect(claims.needsRefresh(now: Date(timeIntervalSince1970: 1_801)))
    }

    @Test func parseValidV2Token() throws {
        let token = Self.jwtFromPayload(["iat": 1_000, "exp": 2_000, "ver": 2])

        let claims = try #require(DeviceTokenClaims.parse(token))

        #expect(claims.issuedAt == Date(timeIntervalSince1970: 1_000))
        #expect(claims.expiresAt == Date(timeIntervalSince1970: 2_000))
        #expect(claims.version == 2)
        #expect(claims.isV2)
    }

    @Test func needsRefreshEnforcesThirtyDayGraceCutoff() throws {
        let claims = try #require(DeviceTokenClaims.parse(Self.token(payload: ["iat": 1_000.0, "exp": 2_000.0])))

        // Within grace: strictly > 80% TTL
        #expect(!claims.needsRefresh(now: Date(timeIntervalSince1970: 1_800)))
        #expect(claims.needsRefresh(now: Date(timeIntervalSince1970: 1_801)))
        // Expired but within 30-day grace
        #expect(claims.needsRefresh(now: Date(timeIntervalSince1970: 2_000 + 29 * 86_400)))
        #expect(claims.needsRefresh(now: Date(timeIntervalSince1970: 2_000 + 30 * 86_400)))
        // Beyond 30-day grace
        #expect(!claims.needsRefresh(now: Date(timeIntervalSince1970: 2_000 + 30 * 86_400 + 1)))
    }

    @Test func instanceCapabilityRejectsExtraClaimsAndValidatesV2JWT() throws {
        let validPayload: [String: Any] = [
            "iss": "solstone-relay",
            "sub": "instance:inst-1",
            "aud": "spl-relay",
            "scope": "session.dial",
            "ver": 2,
            "instance_id": "inst-1",
            "iat": 1_000,
            "exp": 2_000,
            "jti": "jti-123",
        ]
        let token = Self.jwtFromPayload(validPayload)

        // Valid token with matching RFC3339 expires_at
        #expect(throws: Never.self) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: "1970-01-01T00:33:20Z",
                now: Date(timeIntervalSince1970: 1_500)
            )
        }

        // iss can be any string, not tied to origin host
        var customIssPayload = validPayload
        customIssPayload["iss"] = "any-relay-issuer"
        let customIssToken = Self.jwtFromPayload(customIssPayload)
        #expect(throws: Never.self) {
            try InstanceCapability.validateV2JWT(
                customIssToken,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: "1970-01-01T00:33:20Z",
                now: Date(timeIntervalSince1970: 1_500)
            )
        }

        // Float iat (1.5) rejected
        var floatIatPayload = validPayload
        floatIatPayload["iat"] = 1.5
        let floatIatToken = Self.jwtFromPayload(floatIatPayload)
        #expect(throws: InstanceCapabilityError.invalidJWT) {
            try InstanceCapability.validateV2JWT(
                floatIatToken,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: nil as String?,
                now: Date(timeIntervalSince1970: 1_500)
            )
        }

        // RFC3339 expires_at not matching integer exp rejected
        #expect(throws: InstanceCapabilityError.expiryMismatch) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: "1970-01-01T00:33:21Z", // 2001 != 2000
                now: Date(timeIntervalSince1970: 1_500)
            )
        }

        // Extra claims rejected (device_fp, ca_fp, predecessor, arbitrary)
        for extraKey in ["device_fp", "ca_fp", "predecessor", "unknown_extra"] {
            var withExtra = validPayload
            withExtra[extraKey] = "extra-value"
            let extraToken = Self.jwtFromPayload(withExtra)
            #expect(throws: InstanceCapabilityError.invalidJWT) {
                try InstanceCapability.validateV2JWT(
                    extraToken,
                    expectedInstanceID: "inst-1",
                    expectedExpiresAtRFC3339: nil as String?,
                    now: Date(timeIntervalSince1970: 1_500)
                )
            }
        }

        // Instance mismatch rejected
        #expect(throws: InstanceCapabilityError.instanceMismatch) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-2",
                expectedExpiresAtRFC3339: nil as String?,
                now: Date(timeIntervalSince1970: 1_500)
            )
        }

        // Clock skew up to 60s accepted, 61s rejected
        #expect(throws: Never.self) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: nil as String?,
                now: Date(timeIntervalSince1970: 940) // iat (1000) <= 940 + 60 (1000) -> OK
            )
        }
        #expect(throws: InstanceCapabilityError.clockSkew) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: nil as String?,
                now: Date(timeIntervalSince1970: 939) // iat (1000) > 939 + 60 (999) -> rejected
            )
        }

        // Expired token (now >= exp) rejected
        #expect(throws: InstanceCapabilityError.expired) {
            try InstanceCapability.validateV2JWT(
                token,
                expectedInstanceID: "inst-1",
                expectedExpiresAtRFC3339: nil as String?,
                now: Date(timeIntervalSince1970: 2_000)
            )
        }
    }

    static func token(payload: [String: Double]) -> String {
        "e30.\(Self.base64URL(payload)).sig"
    }

    private static func jwtFromPayload(_ object: [String: Any]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(b64).sig"
    }

    private static func base64URL(_ object: [String: Double]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
