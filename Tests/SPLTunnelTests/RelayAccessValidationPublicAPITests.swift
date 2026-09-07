// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
import SPLTunnel

@Suite("Relay access validation public API")
struct RelayAccessValidationPublicAPITests {
    private let now = Date(timeIntervalSince1970: 1_500)
    private let expiry = "1970-01-01T00:33:20Z"

    private func jwt(_ changes: [String: Any] = [:]) throws -> String {
        var claims: [String: Any] = ["iss": "independent-issuer", "sub": "instance:home", "aud": "spl-relay",
            "scope": "session.dial", "ver": 2, "instance_id": "home", "iat": 1_000, "exp": 2_000, "jti": "secret-jti"]
        claims.merge(changes) { _, new in new }
        let payload = try JSONSerialization.data(withJSONObject: claims).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(payload).sig"
    }

    private func envelope(token: String? = nil, changes: [String: Any] = [:]) throws -> Data {
        var fields: [String: Any] = ["protocol_version": 2, "status": "ready", "relay_origin": "https://Relay.Test:443/",
            "instance_id": "home", "device_token": try token ?? jwt(), "expires_at": expiry]
        fields.merge(changes) { _, new in new }
        return try JSONSerialization.data(withJSONObject: fields)
    }

    @Test func readyAndNotConfiguredAreUsableWithoutTestableImport() throws {
        let token = try jwt()
        let status = try RelayAccessValidation.decode(envelope(token: token), expectedInstanceID: "home", now: now)
        guard case .ready(let ready) = status else { Issue.record("expected ready access"); return }
        #expect(ready.relayOrigin.absoluteString == "https://relay.test")
        #expect(ready.instanceID == "home")
        #expect(ready.deviceToken == token)
        #expect(ready.expiresAt == expiry)
        #expect(!String(reflecting: status).contains(token))
        #expect(!String(describing: ready).contains("secret-jti"))
        let disabled = Data(#"{"protocol_version":2,"status":"not_configured"}"#.utf8)
        #expect(try RelayAccessValidation.decode(disabled, expectedInstanceID: "home", now: now) == .notConfigured)
    }

    @Test func strictEnvelopeRejectsInvalidOrExtraFields() throws {
        for changes: [String: Any] in [["extra": true], ["protocol_version": NSNull()], ["protocol_version": 3],
                                      ["protocol_version": true], ["status": "unknown"], ["instance_id": "other"],
                                      ["expires_at": "1970-01-01T00:33:20.000000001Z"]] {
            let data = try envelope(changes: changes)
            #expect(throws: (any Error).self) { try RelayAccessValidation.decode(data, expectedInstanceID: "home", now: now) }
        }
        for raw in [#"{"protocol_version":2,"status":"not_configured","device_token":"secret"}"#, "null"] {
            #expect(throws: (any Error).self) { try RelayAccessValidation.decode(Data(raw.utf8), expectedInstanceID: "home", now: now) }
        }
        #expect(throws: (any Error).self) { try RelayAccessValidation.decode(Data(repeating: 32, count: 65_537), expectedInstanceID: "home", now: now) }
    }

    @Test func strictTokenChecksTypesClaimsSegmentsAndExpiry() throws {
        for changes: [String: Any] in [["device_fp": "fingerprint"], ["ca_fp": "fingerprint"], ["predecessor": "id"],
                                      ["extra": true], ["iat": true], ["iat": 1000.5], ["exp": 2000.5],
                                      ["ver": NSNull()], ["ver": true], ["aud": "other"], ["scope": "other"],
                                      ["sub": "instance:other"], ["iss": ""], ["jti": ""], ["iat": 1561]] {
            let token = try jwt(changes)
            #expect(throws: (any Error).self) { try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: expiry, now: now) }
        }
        let token = try jwt()
        let payload = String(token.split(separator: ".")[1])
        for malformed in [token + ".extra", ".\(payload).sig", "e30.\(payload).", "e30..sig", "e30.\(payload).sig=", "e30.\(payload).s+g"] {
            #expect(throws: (any Error).self) { try RelayAccessValidation.validateV2Token(malformed, expectedInstanceID: "home", expiresAt: expiry, now: now) }
        }
        try RelayAccessValidation.validateV2Token(jwt(["iat": 1560]), expectedInstanceID: "home", expiresAt: expiry, now: now)
        try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: "1970-01-01T00:33:20.000Z", now: now)
        for expiry in ["1970-01-01T00:33:20Ztrailing", "1970-01-01T00:33:20.000000001Z", "1970-01-01T00:33:20.1Z", "1970-01-01T00:33:20Z\n"] {
            #expect(throws: InstanceCapabilityError.expiryMismatch) {
                try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: expiry, now: now)
            }
        }
        try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: "1970-01-01t00:33:20z", now: now)
        try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: "1970-01-01T01:33:20+01:00", now: now)
        #expect(throws: InstanceCapabilityError.expiryMismatch) {
            try RelayAccessValidation.validateV2Token(jwt(["exp": 5_186_000]), expectedInstanceID: "home",
                expiresAt: "1970-02-30T00:33:20Z", now: now)
        }
        #expect(throws: InstanceCapabilityError.expired) {
            try RelayAccessValidation.validateV2Token(token, expectedInstanceID: "home", expiresAt: expiry, now: Date(timeIntervalSince1970: 2000))
        }
    }

    @Test func originsRejectHiddenComponentsAndNormalizeEffectivePort() throws {
        #expect(try RelayAccessValidation.normalizedOrigin(URL(string: "https://Relay.Test:443/")!).absoluteString == "https://relay.test")
        #expect(try RelayAccessValidation.normalizedOrigin(URL(string: "https://Relay.Test:8443")!).absoluteString == "https://relay.test:8443")
        for raw in ["http://relay.test", "wss://relay.test", "https://user@relay.test", "https://relay.test/path",
                    "https://relay.test?", "https://relay.test#", "https://relay.test:0", "https://relay.test:65536",
                    "https://foo%20bar", "https://foo%2fbar", "https://foo%5cbar"] {
            let url = try #require(URL(string: raw))
            #expect(throws: InstanceCapabilityError.invalidOrigin) { try RelayAccessValidation.normalizedOrigin(url) }
            let data = try envelope(changes: ["relay_origin": raw])
            #expect(throws: (any Error).self) { try RelayAccessValidation.decode(data, expectedInstanceID: "home", now: now) }
        }
    }
}
