// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

enum InstanceCapabilityError: Error, Equatable, Sendable {
    case invalidEnvelope
    case invalidJWT
    case unknownVersion
    case missingField
    case extraFields
    case instanceMismatch
    case originMismatch
    case expiryMismatch
    case expired
    case clockSkew
    case downgradeRejected
}

struct ValidatedCapability: Sendable, Equatable {
    let deviceToken: String
    let expiresAt: String?
    let isV2: Bool
}

enum InstanceCapability {
    static func base64URLDecode(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder == 1 {
            return nil
        }
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }

    static func parseRFC3339Date(_ string: String) -> Date? {
        let formatterWithFraction = ISO8601DateFormatter()
        formatterWithFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatterWithFraction.date(from: string) {
            return date
        }
        let standardFormatter = ISO8601DateFormatter()
        standardFormatter.formatOptions = [.withInternetDateTime]
        return standardFormatter.date(from: string)
    }

    static func normalizeOrigin(_ url: URL) -> (scheme: String, host: String, port: Int)? {
        guard let rawScheme = url.scheme?.lowercased(),
              let rawHost = url.host?.lowercased() else {
            return nil
        }
        let canonicalScheme: String
        let defaultPort: Int
        switch rawScheme {
        case "https", "wss":
            canonicalScheme = "https"
            defaultPort = 443
        case "http", "ws":
            canonicalScheme = "http"
            defaultPort = 80
        default:
            return nil
        }
        let port = url.port ?? defaultPort
        return (canonicalScheme, rawHost, port)
    }

    static func originsMatch(_ a: URL, _ b: URL) -> Bool {
        guard let normA = normalizeOrigin(a),
              let normB = normalizeOrigin(b) else {
            return false
        }
        return normA == normB
    }

    // Single authoritative v2 JWT validator
    static func validateV2JWT(
        _ token: String,
        expectedInstanceID: String,
        expectedExpiresAtRFC3339: String?,
        now: Date
    ) throws {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else {
            throw InstanceCapabilityError.invalidJWT
        }
        let payloadSegment = String(segments[1])
        guard !payloadSegment.isEmpty,
              let payloadData = base64URLDecode(payloadSegment) else {
            throw InstanceCapabilityError.invalidJWT
        }

        let decoder = JSONDecoder()
        let claims: V2JWTClaims
        do {
            claims = try decoder.decode(V2JWTClaims.self, from: payloadData)
        } catch {
            throw InstanceCapabilityError.invalidJWT
        }

        guard claims.ver == 2 else {
            throw InstanceCapabilityError.unknownVersion
        }
        guard claims.aud == "spl-relay" else {
            throw InstanceCapabilityError.invalidJWT
        }
        guard claims.scope == "session.dial" else {
            throw InstanceCapabilityError.invalidJWT
        }
        guard claims.sub == "instance:\(expectedInstanceID)" else {
            throw InstanceCapabilityError.instanceMismatch
        }
        guard claims.instanceID == expectedInstanceID else {
            throw InstanceCapabilityError.instanceMismatch
        }
        guard !claims.iss.isEmpty, !claims.jti.isEmpty else {
            throw InstanceCapabilityError.invalidJWT
        }
        guard claims.exp > claims.iat else {
            throw InstanceCapabilityError.invalidJWT
        }

        let nowEpoch = Int(now.timeIntervalSince1970)
        // Clock skew: iat <= now + 60s
        guard claims.iat <= nowEpoch + 60 else {
            throw InstanceCapabilityError.clockSkew
        }
        // Usable now: now < exp
        guard nowEpoch < claims.exp else {
            throw InstanceCapabilityError.expired
        }

        if let expectedExpiresAtRFC3339 {
            guard let date = parseRFC3339Date(expectedExpiresAtRFC3339) else {
                throw InstanceCapabilityError.expiryMismatch
            }
            let expSeconds = Int(date.timeIntervalSince1970)
            guard expSeconds == claims.exp else {
                throw InstanceCapabilityError.expiryMismatch
            }
        }
    }

    // Bootstrap validation (relay_access object)
    static func validateBootstrap(
        _ envelope: RelayAccessBootstrapEnvelope,
        expectedInstanceID: String,
        expectedOrigin: RelayEndpoint,
        now: Date
    ) throws -> ValidatedCapability {
        guard envelope.protocolVersion == 2 else {
            throw InstanceCapabilityError.unknownVersion
        }
        guard envelope.status == "ready" else {
            throw InstanceCapabilityError.invalidEnvelope
        }
        guard envelope.instanceID == expectedInstanceID else {
            throw InstanceCapabilityError.instanceMismatch
        }
        guard let relayOriginURL = URL(string: envelope.relayOrigin),
              originsMatch(relayOriginURL, expectedOrigin.url) else {
            throw InstanceCapabilityError.originMismatch
        }

        try validateV2JWT(
            envelope.deviceToken,
            expectedInstanceID: expectedInstanceID,
            expectedExpiresAtRFC3339: envelope.expiresAt,
            now: now
        )

        return ValidatedCapability(
            deviceToken: envelope.deviceToken,
            expiresAt: envelope.expiresAt,
            isV2: true
        )
    }

    // HTTP 200 response validation (enroll and refresh)
    static func validateHTTPResponse(
        data: Data,
        expectedInstanceID: String,
        expectedOrigin: RelayEndpoint,
        currentIsV2: Bool,
        now: Date
    ) throws -> ValidatedCapability {
        let envelope: ControlHTTPResponseEnvelope
        do {
            envelope = try JSONDecoder().decode(ControlHTTPResponseEnvelope.self, from: data)
        } catch {
            throw InstanceCapabilityError.invalidEnvelope
        }

        if let version = envelope.protocolVersion {
            guard version == 2 else {
                throw InstanceCapabilityError.unknownVersion
            }
            guard let expiresAt = envelope.expiresAt else {
                throw InstanceCapabilityError.expiryMismatch
            }
            try validateV2JWT(
                envelope.deviceToken,
                expectedInstanceID: expectedInstanceID,
                expectedExpiresAtRFC3339: expiresAt,
                now: now
            )
            return ValidatedCapability(
                deviceToken: envelope.deviceToken,
                expiresAt: expiresAt,
                isV2: true
            )
        } else {
            // protocol_version omitted: legacy v1 check
            if currentIsV2 {
                // Downgrade guard: cannot replace v2 with unversioned v1
                throw InstanceCapabilityError.downgradeRejected
            }
            guard let claims = DeviceTokenClaims.parse(envelope.deviceToken) else {
                throw InstanceCapabilityError.invalidJWT
            }
            // Expired replacement is rejected
            guard now < claims.expiresAt else {
                throw InstanceCapabilityError.expired
            }
            return ValidatedCapability(
                deviceToken: envelope.deviceToken,
                expiresAt: envelope.expiresAt,
                isV2: false
            )
        }
    }
}

// Strict JWT decodable rejecting unknown claims
private struct V2JWTClaims: Decodable {
    let iss: String
    let sub: String
    let aud: String
    let scope: String
    let ver: Int
    let instanceID: String
    let iat: Int
    let exp: Int
    let jti: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case iss
        case sub
        case aud
        case scope
        case ver
        case instanceID = "instance_id"
        case iat
        case exp
        case jti
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let allowed = Set(CodingKeys.allCases.map(\.stringValue))
        // Verify no extra keys exist
        let decoderContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
        for key in decoderContainer.allKeys {
            if !allowed.contains(key.stringValue) {
                throw InstanceCapabilityError.extraFields
            }
        }

        iss = try container.decode(String.self, forKey: .iss)
        sub = try container.decode(String.self, forKey: .sub)
        aud = try container.decode(String.self, forKey: .aud)
        scope = try container.decode(String.self, forKey: .scope)
        ver = try container.decode(Int.self, forKey: .ver)
        instanceID = try container.decode(String.self, forKey: .instanceID)
        iat = try container.decode(Int.self, forKey: .iat)
        exp = try container.decode(Int.self, forKey: .exp)
        jti = try container.decode(String.self, forKey: .jti)
    }
}

struct RelayAccessBootstrapEnvelope: Sendable, Equatable {
    let protocolVersion: Int
    let status: String
    let relayOrigin: String
    let instanceID: String
    let deviceToken: String
    let expiresAt: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case protocolVersion = "protocol_version"
        case status
        case relayOrigin = "relay_origin"
        case instanceID = "instance_id"
        case deviceToken = "device_token"
        case expiresAt = "expires_at"
    }
}

extension RelayAccessBootstrapEnvelope: Decodable {
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let allowed = Set(CodingKeys.allCases.map(\.stringValue))
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
        for key in dynamicContainer.allKeys {
            if !allowed.contains(key.stringValue) {
                throw InstanceCapabilityError.extraFields
            }
        }

        protocolVersion = try container.decode(Int.self, forKey: .protocolVersion)
        status = try container.decode(String.self, forKey: .status)
        relayOrigin = try container.decode(String.self, forKey: .relayOrigin)
        instanceID = try container.decode(String.self, forKey: .instanceID)
        deviceToken = try container.decode(String.self, forKey: .deviceToken)
        expiresAt = try container.decode(String.self, forKey: .expiresAt)
    }
}

private struct ControlHTTPResponseEnvelope: Decodable {
    let protocolVersion: Int?
    let deviceToken: String
    let expiresAt: String?

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case deviceToken = "device_token"
        case expiresAt = "expires_at"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.protocolVersion) {
            if try container.decodeNil(forKey: .protocolVersion) {
                throw InstanceCapabilityError.invalidEnvelope
            }
            protocolVersion = try container.decode(Int.self, forKey: .protocolVersion)
        } else {
            protocolVersion = nil
        }
        deviceToken = try container.decode(String.self, forKey: .deviceToken)
        expiresAt = try container.decodeIfPresent(String.self, forKey: .expiresAt)
    }
}

private struct DynamicCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}
