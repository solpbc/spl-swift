// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("StoredPairing Codable")
struct StoredPairingCodableTests {
    @Test func encodingWritesRelayEnrollmentAndOmitsLegacyDeviceToken() throws {
        let data = try Self.encoder.encode(fixture())
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])

        #expect(object["relayEnrollment"] != nil)
        #expect(object["deviceToken"] == nil)
    }

    @Test func legacyDeviceTokenDecodesAsEnrolled() throws {
        let pairing = try Self.decoder.decode(
            StoredPairing.self,
            from: Self.payload(extra: ["deviceToken": "legacy-token"])
        )

        #expect(pairing.relayEnrollment == .enrolled(deviceToken: "legacy-token", expiresAt: nil))
    }

    @Test func missingRelayEnrollmentDecodesAsUnavailable() throws {
        let pairing = try Self.decoder.decode(StoredPairing.self, from: Self.payload(extra: [:]))

        #expect(pairing.relayEnrollment == .unavailable)
    }

    @Test func bothRelayEnrollmentAndLegacyDeviceTokenPrefersRelayEnrollment() throws {
        let pairing = try Self.decoder.decode(StoredPairing.self, from: Self.payload(extra: [
            "deviceToken": "legacy-token",
            "relayEnrollment": [
                "enrolled": [
                    "deviceToken": "current-token",
                    "expiresAt": "2036-01-01T00:00:00Z",
                ],
            ],
        ]))

        #expect(pairing.relayEnrollment == .enrolled(deviceToken: "current-token", expiresAt: "2036-01-01T00:00:00Z"))
    }

    @Test func relayEnrollmentRoundTripsExpiresAt() throws {
        // L5 correction pins non-nil relay enrollment expiry round-trip in the existing L1 suite.
        let pairing = StoredPairing(
            instanceID: "expires-at",
            homeLabel: "home",
            relayEndpoint: "wss://relay.example.com",
            fingerprint: "sha256:\(String(repeating: "b", count: 64))",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: .enrolled(deviceToken: "current-token", expiresAt: "2036-01-01T00:00:00Z"),
            localEndpoints: [],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )

        let decoded = try Self.decoder.decode(StoredPairing.self, from: Self.encoder.encode(pairing))

        #expect(decoded.relayEnrollment == .enrolled(deviceToken: "current-token", expiresAt: "2036-01-01T00:00:00Z"))
    }

    @Test func currentRelayEnrollmentWithoutExpiresAtDecodesAsNil() throws {
        // L5 correction pins nil expiry decode for current relay enrollment in the existing L1 suite.
        let pairing = try Self.decoder.decode(StoredPairing.self, from: Self.payload(extra: [
            "relayEnrollment": [
                "enrolled": [
                    "deviceToken": "current-token",
                ],
            ],
        ]))

        #expect(pairing.relayEnrollment == .enrolled(deviceToken: "current-token", expiresAt: nil))
    }

    @Test func localEndpointEncodesCanonicalIPKeyAndDecodesBothWireShapes() throws {
        let endpoint = LocalEndpoint(host: "192.168.1.10", port: 7657, scope: "lan")
        let data = try Self.encoder.encode(endpoint)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains(#""ip""#))
        #expect(!json.contains(#""host""#))
        #expect(try Self.decoder.decode(LocalEndpoint.self, from: data) == endpoint)

        let canonical = Data(#"{"ip":"192.168.4.27","port":7657,"scope":"lan"}"#.utf8)
        #expect(try Self.decoder.decode(LocalEndpoint.self, from: canonical)
            == LocalEndpoint(host: "192.168.4.27", port: 7657, scope: "lan"))
        let canonicalReencoded = try Self.encoder.encode(try Self.decoder.decode(LocalEndpoint.self, from: canonical))
        let canonicalJSON = try #require(String(data: canonicalReencoded, encoding: .utf8))
        #expect(canonicalJSON.contains(#""ip""#))
        #expect(!canonicalJSON.contains(#""host""#))

        let legacy = Data(#"{"host":"192.168.1.10","port":7657,"scope":"lan"}"#.utf8)
        #expect(try Self.decoder.decode(LocalEndpoint.self, from: legacy) == endpoint)
        let legacyReencoded = try Self.encoder.encode(try Self.decoder.decode(LocalEndpoint.self, from: legacy))
        let legacyJSON = try #require(String(data: legacyReencoded, encoding: .utf8))
        #expect(legacyJSON.contains(#""ip""#))
        #expect(!legacyJSON.contains(#""host""#))
    }

    @Test func legacyRecordWithLocalEndpointDecodesWithoutEndpointLoss() throws {
        let pairing = try Self.decoder.decode(StoredPairing.self, from: Self.payload(extra: [
            "deviceToken": "legacy-token",
            "localEndpoints": [
                [
                    "host": "192.168.1.10",
                    "port": 7657,
                    "scope": "lan",
                ],
            ],
        ]))

        #expect(pairing.localEndpoints == [LocalEndpoint(host: "192.168.1.10", port: 7657, scope: "lan")])
        #expect(pairing.relayEnrollment == .enrolled(deviceToken: "legacy-token", expiresAt: nil))
    }

    @Test func updatingRelayEnrollmentPreservesAllStoredPairingFields() throws {
        let original = StoredPairing(
            instanceID: "instance-1",
            homeLabel: "home",
            relayEndpoint: "wss://relay.example.com",
            fingerprint: "sha256:\(String(repeating: "c", count: 64))",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: .unavailable,
            localEndpoints: [LocalEndpoint(host: "192.168.1.10", port: 7657, scope: "lan")],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_100)
        )

        let updated = original.updatingRelayEnrollment(.enrolled(
            deviceToken: "new-token",
            expiresAt: "2036-01-01T00:00:00Z"
        ))

        #expect(updated.instanceID == original.instanceID)
        #expect(updated.homeLabel == original.homeLabel)
        #expect(updated.relayEndpoint == original.relayEndpoint)
        #expect(updated.fingerprint == original.fingerprint)
        #expect(updated.clientCertPEM == original.clientCertPEM)
        #expect(updated.clientKeyPEM == original.clientKeyPEM)
        #expect(updated.caChainPEM == original.caChainPEM)
        #expect(updated.localEndpoints == original.localEndpoints)
        #expect(updated.pairedAt == original.pairedAt)
        #expect(updated.relayEnrollment == .enrolled(deviceToken: "new-token", expiresAt: "2036-01-01T00:00:00Z"))
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    private func fixture(instanceID: String = "instance-1") -> StoredPairing {
        StoredPairing(
            instanceID: instanceID,
            homeLabel: "living room mac",
            relayEndpoint: "https://spl.solpbc.org",
            fingerprint: "sha256:abcdef",
            clientCertPEM: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            clientKeyPEM: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            caChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
            relayEnrollment: .enrolled(deviceToken: "device-token", expiresAt: nil),
            localEndpoints: [],
            pairedAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }

    private static func payload(extra: [String: Any]) throws -> Data {
        var payload: [String: Any] = [
            "instanceID": "instance",
            "homeLabel": "home",
            "relayEndpoint": "wss://relay.example.com",
            "fingerprint": "sha256:\(String(repeating: "a", count: 64))",
            "clientCertPEM": "cert",
            "clientKeyPEM": "key",
            "caChainPEM": "ca",
            "localEndpoints": [],
            "pairedAt": "2026-01-01T00:00:00Z",
        ]
        for (key, value) in extra {
            payload[key] = value
        }
        return try JSONSerialization.data(withJSONObject: payload)
    }
}
