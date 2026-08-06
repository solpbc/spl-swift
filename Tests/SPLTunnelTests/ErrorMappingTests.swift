// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Network
import Testing
@testable import SPLTunnel

@Suite("ErrorMapping")
struct ErrorMappingTests {
    @Test func relay401And403DialErrorsMapToAuthRefreshRequired() {
        // Relay authorization failures must map to auth-refresh-required session errors.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayUnauthorized) == .authRefreshRequired)
    }

    @Test func relayClose4401MapsToAuthRefreshRequired() {
        // WebSocket close code 4401 must surface as an auth-refresh-required session error.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayCloseUnauthorized) == .authRefreshRequired)
    }

    @Test func relay402MapsToNotEntitled() {
        // Relay payment-required failures must map to not-entitled session errors.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayNotEntitled) == .notEntitled)
    }

    @Test func innerTLSErrorMapsToTLSFailed() throws {
        // Inner TLS failures must map to TLS-failed session errors.
        let mapped = RaceCoordinator<Int>.sessionError(from: InnerTLSError.peerNotPinned)
        guard case .tlsFailed(let message) = mapped else {
            Issue.record("Expected tlsFailed, got \(mapped)")
            return
        }
        #expect(message == "peerNotPinned")
    }

    @Test func peerAccessDeniedClassifierRecognizesOnlyAccessDenied() {
        // Security/SecBase.h: errSSLPeerAccessDenied is the sole terminal TLS status.
        #expect(isPeerAccessDenied(NWError.tls(-9832)))
        #expect(isPeerAccessDenied(NWError.tls(-9838)) == false)
        #expect(isPeerAccessDenied(NWError.tls(-9800)) == false)
        #expect(isPeerAccessDenied(NWError.posix(.ECONNREFUSED)) == false)
    }

    @Test func peerAccessDeniedMapsToRevoked() {
        // Security/SecBase.h: access denied is a terminal session revocation signal.
        #expect(RaceCoordinator<Int>.sessionError(from: NWError.tls(-9832)) == .revoked)
    }

    @Test func otherDialErrorMapsToUnreachable() {
        // Other dial errors must fall back to unreachable session errors.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.connectTimeout) == .unreachable)
    }

    @Test func aggregateFailurePrecedence() {
        // Revocation short-circuits before aggregation; aggregate preserves remaining precedence.
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawNotEntitled: true,
            sawAuthRefreshRequired: true
        ) == .notEntitled)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawNotEntitled: false,
            sawAuthRefreshRequired: true
        ) == .authRefreshRequired)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawNotEntitled: false,
            sawAuthRefreshRequired: false
        ) == .unreachable)
    }
}
