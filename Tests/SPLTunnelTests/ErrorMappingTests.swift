// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Testing
@testable import SPLTunnel

@Suite("ErrorMapping")
struct ErrorMappingTests {
    @Test func relay401And403DialErrorsMapToAuthRefreshRequired() {
        // S15 pins the single DialError -> SessionError mapping.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayUnauthorized) == .authRefreshRequired)
    }

    @Test func relayClose4401MapsToAuthRefreshRequired() {
        // S15 pins tokens.md:260 4401 close surfacing through DialError.relayCloseUnauthorized.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayCloseUnauthorized) == .authRefreshRequired)
    }

    @Test func relay402MapsToNotEntitled() {
        // S15 pins the single DialError -> SessionError mapping.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.relayNotEntitled) == .notEntitled)
    }

    @Test func innerTLSErrorMapsToTLSFailed() throws {
        // S15 pins the single InnerTLSError -> SessionError mapping.
        let mapped = RaceCoordinator<Int>.sessionError(from: InnerTLSError.peerNotPinned)
        guard case .tlsFailed(let message) = mapped else {
            Issue.record("Expected tlsFailed, got \(mapped)")
            return
        }
        #expect(message == "peerNotPinned")
    }

    @Test func otherDialErrorMapsToUnreachable() {
        // S15 pins the fallback mapping.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.connectTimeout) == .unreachable)
    }

    @Test func aggregateFailurePrecedence() {
        // S15 pins aggregate precedence revoked > notEntitled > authRefreshRequired > unreachable.
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
