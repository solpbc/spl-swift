// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

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

    @Test func otherDialErrorMapsToUnreachable() {
        // Other dial errors must fall back to unreachable session errors.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.connectTimeout) == .unreachable)
    }

    @Test func aggregateFailurePrecedence() {
        // Aggregate failure precedence is revoked, not-entitled, auth-refresh-required, then unreachable.
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawRevocation: true,
            sawNotEntitled: true,
            sawAuthRefreshRequired: true
        ) == .revoked)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawRevocation: false,
            sawNotEntitled: true,
            sawAuthRefreshRequired: true
        ) == .notEntitled)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawRevocation: false,
            sawNotEntitled: false,
            sawAuthRefreshRequired: true
        ) == .authRefreshRequired)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawRevocation: false,
            sawNotEntitled: false,
            sawAuthRefreshRequired: false
        ) == .unreachable)
    }
}
