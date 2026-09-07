// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public struct DeviceTokenClaims: Sendable, Equatable {
    public let issuedAt: Date
    public let expiresAt: Date
    public let version: Int?

    public var isV2: Bool {
        version == 2
    }

    public init(issuedAt: Date, expiresAt: Date, version: Int? = nil) {
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.version = version
    }

    public static func parse(_ token: String) -> DeviceTokenClaims? {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else {
            return nil
        }

        let payload = String(segments[1])
        guard !payload.isEmpty,
              let data = InstanceCapability.base64URLDecode(payload)
        else {
            return nil
        }

        do {
            let decoded = try JSONDecoder().decode(Payload.self, from: data)
            return DeviceTokenClaims(
                issuedAt: Date(timeIntervalSince1970: decoded.iat),
                expiresAt: Date(timeIntervalSince1970: decoded.exp),
                version: decoded.ver
            )
        } catch {
            return nil
        }
    }

    public static func needsRefresh(token: String?, now: Date) -> Bool {
        guard let token,
              let claims = Self.parse(token)
        else {
            return true
        }
        return claims.needsRefresh(now: now)
    }

    public func needsRefresh(now: Date) -> Bool {
        let ttl = expiresAt.timeIntervalSince(issuedAt)
        guard ttl > 0 else {
            return true
        }
        let graceCutoff = expiresAt.addingTimeInterval(30.0 * 86400.0)
        guard now <= graceCutoff else {
            return false
        }
        let age = now.timeIntervalSince(issuedAt)
        return age / ttl > 0.80
    }
}

private struct Payload: Decodable {
    let exp: Double
    let iat: Double
    let ver: Int?
}
