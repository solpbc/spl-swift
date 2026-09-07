// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public struct ReadyRelayAccess: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let relayOrigin: URL
    public let instanceID: String
    public let deviceToken: String
    public let expiresAt: String
    public var description: String { "ReadyRelayAccess(<redacted>)" }
    public var debugDescription: String { description }
}

public enum RelayAccessStatus: Sendable, Equatable {
    case ready(ReadyRelayAccess)
    case notConfigured
}

// Decode checks for responses received through an authenticated home connection.
// The relay verifies the JWT signature when the capability is used.
public enum RelayAccessValidation {
    public static func normalizedOrigin(_ url: URL) throws -> URL {
        guard url.scheme?.lowercased() == "https" else { throw InstanceCapabilityError.invalidOrigin }
        return try InstanceCapability.normalizedOrigin(url)
    }

    public static func decode(_ data: Data, expectedInstanceID: String, now: Date = Date()) throws -> RelayAccessStatus {
        guard data.count <= 65536 else { throw InstanceCapabilityError.invalidEnvelope }
        let envelope: AccessEnvelope
        do { envelope = try JSONDecoder().decode(AccessEnvelope.self, from: data) }
        catch { throw InstanceCapabilityError.invalidEnvelope }
        guard envelope.protocolVersion == 2 else { throw InstanceCapabilityError.unknownVersion }
        if envelope.status == "not_configured" { return .notConfigured }
        guard let ready = envelope.ready,
              let url = URL(string: ready.relayOrigin) else { throw InstanceCapabilityError.invalidEnvelope }
        let origin = try normalizedOrigin(url)
        _ = try InstanceCapability.validateBootstrap(ready, expectedInstanceID: expectedInstanceID,
                                                  expectedOrigin: RelayEndpoint(origin), now: now)
        return .ready(ReadyRelayAccess(relayOrigin: origin, instanceID: ready.instanceID,
                                      deviceToken: ready.deviceToken, expiresAt: ready.expiresAt))
    }

    public static func validateV2Token(_ token: String, expectedInstanceID: String, expiresAt: String, now: Date = Date()) throws {
        try InstanceCapability.validateV2JWT(token, expectedInstanceID: expectedInstanceID,
                                             expectedExpiresAtRFC3339: expiresAt, now: now)
    }
}

private struct AccessEnvelope: Decodable {
    let protocolVersion: Int
    let status: String
    let ready: RelayAccessBootstrapEnvelope?

    private enum Keys: String, CodingKey { case protocolVersion = "protocol_version", status }
    private struct AnyKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        protocolVersion = try c.decode(Int.self, forKey: .protocolVersion)
        status = try c.decode(String.self, forKey: .status)
        if status == "not_configured" {
            let all = try decoder.container(keyedBy: AnyKey.self)
            guard Set(all.allKeys.map(\.stringValue)) == ["protocol_version", "status"] else {
                throw InstanceCapabilityError.extraFields
            }
            ready = nil
        } else if status == "ready" {
            ready = try RelayAccessBootstrapEnvelope(from: decoder)
        } else { throw InstanceCapabilityError.invalidEnvelope }
    }
}
