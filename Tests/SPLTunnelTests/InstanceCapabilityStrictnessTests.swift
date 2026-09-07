// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

// tokens.md v2 decode contract: three nonempty JWT segments and exact integer expiry.
@Suite("Instance capability strictness regressions")
struct InstanceCapabilityStrictnessTests {
    private func token() throws -> String {
        let claims: [String: Any] = ["iss": "relay", "sub": "instance:home", "aud": "spl-relay",
            "scope": "session.dial", "ver": 2, "instance_id": "home", "iat": 1000, "exp": 2000, "jti": "jti"]
        let payload = try JSONSerialization.data(withJSONObject: claims).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(payload).sig"
    }

    @Test func rejectsAdditionalJWTPart() throws {
        let valid = try token()
        try InstanceCapability.validateV2JWT(valid, expectedInstanceID: "home",
            expectedExpiresAtRFC3339: "1970-01-01T00:33:20Z", now: Date(timeIntervalSince1970: 1500))
        #expect(throws: (any Error).self) {
            try InstanceCapability.validateV2JWT(valid + ".extra", expectedInstanceID: "home",
                expectedExpiresAtRFC3339: "1970-01-01T00:33:20Z", now: Date(timeIntervalSince1970: 1500))
        }
    }

    @Test func rejectsFractionalExpiryInsteadOfTruncatingIt() throws {
        let valid = try token()
        #expect(throws: (any Error).self) {
            try InstanceCapability.validateV2JWT(valid, expectedInstanceID: "home",
                expectedExpiresAtRFC3339: "1970-01-01T00:33:20.5Z", now: Date(timeIntervalSince1970: 1500))
        }
    }
}
