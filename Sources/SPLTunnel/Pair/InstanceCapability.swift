// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public enum InstanceCapabilityError: Error, Equatable, Sendable {
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
    case invalidOrigin
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
        if let date = formatterWithFraction.date(from: string.uppercased()) {
            return date
        }
        let standardFormatter = ISO8601DateFormatter()
        standardFormatter.formatOptions = [.withInternetDateTime]
        return standardFormatter.date(from: string.uppercased())
    }

    static func normalizedOrigin(_ url: URL, allowInsecure: Bool = false) throws -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let rawScheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              !host.unicodeScalars.contains(where: {
                  $0.value <= 32 || $0.value == 127 || "/\\?#@%".unicodeScalars.contains($0)
              }),
              !url.absoluteString.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }),
              components.port.map({ (1...65535).contains($0) }) ?? true else {
            throw InstanceCapabilityError.invalidOrigin
        }
        let secure = rawScheme == "https" || rawScheme == "wss"
        guard secure || (allowInsecure && (rawScheme == "http" || rawScheme == "ws")) else {
            throw InstanceCapabilityError.invalidOrigin
        }
        components.scheme = secure ? "https" : "http"
        components.host = host.lowercased()
        if components.port == (secure ? 443 : 80) { components.port = nil }
        components.path = ""
        guard let result = components.url else { throw InstanceCapabilityError.invalidOrigin }
        return result
    }

    static func normalizeOrigin(_ url: URL) -> (scheme: String, host: String, port: Int)? {
        guard let origin = try? normalizedOrigin(url, allowInsecure: true),
              let scheme = origin.scheme, let host = origin.host else { return nil }
        return (scheme, host, origin.port ?? (scheme == "https" ? 443 : 80))
    }

    static func payload(_ token: String) throws -> Data {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy {
                  (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
              } }),
              let data = base64URLDecode(String(segments[1])) else {
            throw InstanceCapabilityError.invalidJWT
        }
        return data
    }

    static func validateTimes(iat: Int, exp: Int, now: Date, requireUsable: Bool) throws {
        let maxSafeInteger = 9_007_199_254_740_991
        guard iat >= 0, exp > iat, exp <= maxSafeInteger else {
            throw InstanceCapabilityError.invalidJWT
        }
        let sampledNow = now.timeIntervalSince1970
        guard sampledNow.isFinite else { throw InstanceCapabilityError.invalidJWT }
        guard Double(iat) <= floor(sampledNow) + 60 else { throw InstanceCapabilityError.clockSkew }
        if requireUsable && sampledNow >= Double(exp) { throw InstanceCapabilityError.expired }
    }

    static func validateExpiry(_ value: String?, exp: Int) throws {
        guard let value else { return }
        let rfc3339 = #"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$"#
        guard value.range(of: rfc3339, options: .regularExpression) == value.startIndex..<value.endIndex else {
            throw InstanceCapabilityError.expiryMismatch
        }
        // Reject nonzero fractions before Foundation can round submillisecond precision.
        if let dot = value.firstIndex(of: ".") {
            let digits = value[value.index(after: dot)...].prefix(while: { $0.isASCII && $0.isNumber })
            guard !digits.isEmpty, digits.allSatisfy({ $0 == "0" }) else {
                throw InstanceCapabilityError.expiryMismatch
            }
        }
        guard let date = parseRFC3339Date(value), date.timeIntervalSince1970 == Double(exp) else {
            throw InstanceCapabilityError.expiryMismatch
        }
        let normalized = value.uppercased()
        var offset = 0
        if !normalized.hasSuffix("Z") {
            let suffix = Array(normalized.suffix(6))
            guard let hours = Int(String(suffix[1...2])), hours <= 23,
                  let minutes = Int(String(suffix[4...5])), minutes <= 59 else {
                throw InstanceCapabilityError.expiryMismatch
            }
            offset = (hours * 3600 + minutes * 60) * (suffix[0] == "-" ? -1 : 1)
        }
        guard let zone = TimeZone(secondsFromGMT: offset) else { throw InstanceCapabilityError.expiryMismatch }
        let roundTrip = ISO8601DateFormatter()
        roundTrip.formatOptions = [.withInternetDateTime]
        roundTrip.timeZone = zone
        // Foundation normalizes impossible calendar dates; compare the supplied civil time too.
        guard roundTrip.string(from: date).prefix(19) == normalized.prefix(19) else {
            throw InstanceCapabilityError.expiryMismatch
        }
    }

    static func validateLegacyJWT(_ token: String, expectedInstanceID: String, expiresAt: String?, now: Date, requireUsable: Bool = true) throws {
        let claims: LegacyJWTClaims
        do { claims = try JSONDecoder().decode(LegacyJWTClaims.self, from: payload(token)) }
        catch { throw InstanceCapabilityError.invalidJWT }
        guard claims.instanceID == expectedInstanceID else { throw InstanceCapabilityError.instanceMismatch }
        guard claims.aud == "spl-relay", claims.scope == "session.dial",
              claims.sub.hasPrefix("device:"), claims.sub.count > 7,
              !claims.iss.isEmpty, !claims.jti.isEmpty,
              claims.deviceFP.hasPrefix("sha256:"), claims.deviceFP.utf8.count == 71,
              claims.deviceFP.dropFirst(7).allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
            throw InstanceCapabilityError.invalidJWT
        }
        try validateTimes(iat: claims.iat, exp: claims.exp, now: now, requireUsable: requireUsable)
        try validateExpiry(expiresAt, exp: claims.exp)
    }

    static func renewalIsV2(_ token: String, expectedInstanceID: String, now: Date) throws -> Bool {
        let data = try payload(token)
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw InstanceCapabilityError.invalidJWT
        }
        if object.keys.contains("ver") {
            try validateV2JWT(token, expectedInstanceID: expectedInstanceID, expectedExpiresAtRFC3339: nil,
                              now: now, requireUsable: false)
            return true
        }
        try validateLegacyJWT(token, expectedInstanceID: expectedInstanceID, expiresAt: nil,
                              now: now, requireUsable: false)
        return false
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
        now: Date,
        requireUsable: Bool = true
    ) throws {
        let payloadData = try payload(token)

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
        try validateTimes(iat: claims.iat, exp: claims.exp, now: now, requireUsable: requireUsable)
        try validateExpiry(expectedExpiresAtRFC3339, exp: claims.exp)
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
            try validateLegacyJWT(envelope.deviceToken, expectedInstanceID: expectedInstanceID,
                                  expiresAt: envelope.expiresAt, now: now)
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

private struct LegacyJWTClaims: Decodable {
    let iss: String
    let sub: String
    let aud: String
    let scope: String
    let instanceID: String
    let deviceFP: String
    let iat: Int
    let exp: Int
    let jti: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case iss, sub, aud, scope, iat, exp, jti
        case instanceID = "instance_id"
        case deviceFP = "device_fp"
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.stringValue))
        guard Set(dynamic.allKeys.map(\.stringValue)) == allowed else {
            throw InstanceCapabilityError.extraFields
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        iss = try c.decode(String.self, forKey: .iss)
        sub = try c.decode(String.self, forKey: .sub)
        aud = try c.decode(String.self, forKey: .aud)
        scope = try c.decode(String.self, forKey: .scope)
        instanceID = try c.decode(String.self, forKey: .instanceID)
        deviceFP = try c.decode(String.self, forKey: .deviceFP)
        iat = try c.decode(Int.self, forKey: .iat)
        exp = try c.decode(Int.self, forKey: .exp)
        jti = try c.decode(String.self, forKey: .jti)
    }
}
