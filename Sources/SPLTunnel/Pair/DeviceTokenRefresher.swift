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
    private let clientInfo: SPLClientInfo

    public init(clientInfo: SPLClientInfo) {
        self.init(session: .shared, clientInfo: clientInfo)
    }

    init(session: URLSession, clientInfo: SPLClientInfo) {
        self.session = session
        self.clientInfo = clientInfo
    }

    public func refreshIfNeeded(pairing: StoredPairing, now: Date) async -> DeviceTokenRefreshResult {
        guard case .enrolled(let deviceToken, _) = pairing.relayEnrollment else {
            return .notNeeded(pairing)
        }
        guard DeviceTokenClaims.needsRefresh(token: deviceToken, now: now) else {
            return .notNeeded(pairing)
        }
        return await refreshNow(pairing: pairing)
    }

    public func refreshNow(pairing: StoredPairing) async -> DeviceTokenRefreshResult {
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
                deviceToken: deviceToken,
                userAgent: clientInfo.userAgent
            )
        } catch {
            return .transientFailure(pairing)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            return .transientFailure(pairing)
        }

        guard let http = response as? HTTPURLResponse else {
            return .transientFailure(pairing)
        }

        switch http.statusCode {
        case 200:
            do {
                let relayResponse = try PairClient.decodeRelayResponse(data: data)
                return .refreshed(pairing.updatingRelayEnrollment(.enrolled(
                    deviceToken: relayResponse.deviceToken,
                    expiresAt: relayResponse.expiresAt
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

    static func makeRefreshRequest(relayEndpoint: RelayEndpoint, deviceToken: String, userAgent: String) throws -> URLRequest {
        var request = URLRequest(url: try PairClient.controlURL(relayEndpoint, path: "token/refresh"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode(RelayRefreshRequest(deviceToken: deviceToken))
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

    enum CodingKeys: String, CodingKey {
        case deviceToken = "device_token"
    }
}

private struct RelayErrorResponse: Decodable {
    let error: String?
    let reason: String?
}
