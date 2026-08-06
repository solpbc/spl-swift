// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import SPLTunnel
import Testing

@Suite("InnerTLSError Public API")
struct InnerTLSErrorPublicAPITests {
    @Test func publicCasesRemainPreAccessDeniedSurface() {
        let errors: [InnerTLSError] = [
            .invalidPort(443),
            .identityAssemblyFailed,
            .invalidCertificate,
            .invalidPrivateKey,
            .peerNotPinned,
            .caFingerprintMismatch,
            .handshakeFailed("test"),
            .sendFailed("test"),
            .receiveFailed("test"),
            .closed,
        ]

        #expect(errors.map(publicCaseName) == [
            "invalidPort",
            "identityAssemblyFailed",
            "invalidCertificate",
            "invalidPrivateKey",
            "peerNotPinned",
            "caFingerprintMismatch",
            "handshakeFailed",
            "sendFailed",
            "receiveFailed",
            "closed",
        ])
    }

    private func publicCaseName(_ error: InnerTLSError) -> String {
        switch error {
        case .invalidPort:
            "invalidPort"
        case .identityAssemblyFailed:
            "identityAssemblyFailed"
        case .invalidCertificate:
            "invalidCertificate"
        case .invalidPrivateKey:
            "invalidPrivateKey"
        case .peerNotPinned:
            "peerNotPinned"
        case .caFingerprintMismatch:
            "caFingerprintMismatch"
        case .handshakeFailed:
            "handshakeFailed"
        case .sendFailed:
            "sendFailed"
        case .receiveFailed:
            "receiveFailed"
        case .closed:
            "closed"
        }
    }
}
