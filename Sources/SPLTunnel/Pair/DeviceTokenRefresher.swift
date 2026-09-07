// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public enum DeviceTokenRefreshResult: Sendable, Equatable {
    case refreshed(StoredPairing)
    case notNeeded(StoredPairing)
    case transientFailure(StoredPairing)
    case definitiveAuthFailure
}

public struct DeviceTokenRefresher: Sendable {
    private let session: URLSession

    public init(clientInfo: SPLClientInfo) {
        self.init(session: .shared, clientInfo: clientInfo)
    }

    init(session: URLSession, clientInfo: SPLClientInfo) {
        self.session = session
    }

    public func refreshIfNeeded(pairing: StoredPairing, now: Date) async -> DeviceTokenRefreshResult {
        guard case .enrolled(let deviceToken, _) = pairing.relayEnrollment else {
            return .notNeeded(pairing)
        }
        guard DeviceTokenClaims.needsRefresh(token: deviceToken, now: now) else {
            return .notNeeded(pairing)
        }
        return await refreshNow(pairing: pairing, now: now)
    }

    public func refreshNow(pairing: StoredPairing, now: Date = Date()) async -> DeviceTokenRefreshResult {
        guard case .enrolled(let deviceToken, _) = pairing.relayEnrollment else {
            return .notNeeded(pairing)
        }
        guard let relayEndpoint = URL(string: pairing.relayEndpoint) else {
            return .transientFailure(pairing)
        }
        guard let validatedRelayEndpoint = try? RelayEndpoint(relayEndpoint) else {
            return .transientFailure(pairing)
        }

        let request: URLRequest
        do {
            request = try Self.makeRefreshRequest(
                relayEndpoint: validatedRelayEndpoint,
                deviceToken: deviceToken
            )
        } catch {
            return .transientFailure(pairing)
        }

        let status: Int
        let data: Data
        do {
            (status, data, _) = try await BoundedHTTPClient.send(request: request, session: session)
        } catch {
            return .transientFailure(pairing)
        }

        switch status {
        case 200:
            let currentIsV2 = DeviceTokenClaims.parse(deviceToken)?.isV2 ?? false
            do {
                let validated = try InstanceCapability.validateHTTPResponse(
                    data: data,
                    expectedInstanceID: pairing.instanceID,
                    expectedOrigin: validatedRelayEndpoint,
                    currentIsV2: currentIsV2,
                    now: now
                )
                return .refreshed(pairing.updatingRelayEnrollment(.enrolled(
                    deviceToken: validated.deviceToken,
                    expiresAt: validated.expiresAt
                )))
            } catch {
                return .transientFailure(pairing)
            }
        case 401:
            if Self.errorReason(from: data) == "expired" {
                return .definitiveAuthFailure
            }
            return .transientFailure(pairing)
        case 403:
            if Self.errorField(from: data) == "instance revoked" {
                return .definitiveAuthFailure
            }
            return .transientFailure(pairing)
        default:
            return .transientFailure(pairing)
        }
    }

    static func makeRefreshRequest(relayEndpoint: RelayEndpoint, deviceToken: String) throws -> URLRequest {
        var request = URLRequest(url: try PairClient.controlURL(relayEndpoint, path: "token/refresh"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(RelayWire.userAgent, forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode(RelayRefreshRequest(
            deviceToken: deviceToken,
            protocolVersion: 2
        ))
        return request
    }

    private static func errorReason(from data: Data) -> String? {
        try? JSONDecoder().decode(RelayErrorResponse.self, from: data).reason
    }

    private static func errorField(from data: Data) -> String? {
        try? JSONDecoder().decode(RelayErrorResponse.self, from: data).error
    }
}

private struct RelayRefreshRequest: Encodable {
    let deviceToken: String
    let protocolVersion: Int

    enum CodingKeys: String, CodingKey {
        case deviceToken = "device_token"
        case protocolVersion = "protocol_version"
    }
}

private struct RelayErrorResponse: Decodable {
    let error: String?
    let reason: String?
}
