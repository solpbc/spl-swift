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

    @Test func receivedAlertsAreTheJournalsVerdictAndNothingElseIs() {
        // proto/session.md § 7: 49 stops, 46 retries, every other received alert is counted.
        // Falsified by narrowing the counted branch to recognised codes (no_renegotiation and the
        // generic received-alert status would then read as unreachable), by dropping the
        // record-layer alerts, or by counting a close, a reset or a local record failure.
        #expect(HandshakeFailure.verdict(from: NWError.tls(PeerAlert.accessDenied)) == .accessDenied)
        #expect(HandshakeFailure.verdict(from: TLSPeerAlert(status: PeerAlert.accessDenied)) == .accessDenied)
        #expect(HandshakeFailure.verdict(from: NWError.tls(PeerAlert.certificateUnknown)) == .certificateUnknown)
        for status in [
            PeerAlert.internalError,
            PeerAlert.badCertificate,
            PeerAlert.unexpectedMessage,
            PeerAlert.badRecordMac,
            PeerAlert.recordOverflow,
            PeerAlert.genericFatal,
            Int32(-9840), // no_renegotiation, a code no journal sends
            Int32(-9831), // unknown_ca
        ] {
            #expect(HandshakeFailure.verdict(from: NWError.tls(status)) == .refused, "status \(status)")
            #expect(HandshakeFailure.verdict(from: TLSPeerAlert(status: status)) == .refused, "status \(status)")
        }
        let notVerdicts: [any Error] = [
            NWError.tls(PeerAlert.closedGraceful),
            NWError.tls(PeerAlert.closedAbort),
            NWError.tls(PeerAlert.closedNoNotify),
            NWError.tls(PeerAlert.localDecryptionFailure),
            NWError.tls(PeerAlert.localBadRecordMac),
            NWError.tls(-9800), // errSSLProtocol, detected locally
            NWError.tls(-9830), // errSSLIllegalParam, inside the peer range but local
            NWError.tls(-9841), // errSSLPeerAuthCompleted, not an alert
            NWError.posix(.ECONNRESET),
            NWError.posix(.ECONNREFUSED),
            InnerTLSError.receiveFailed("closed"),
            SessionError.revoked,
        ]
        for error in notVerdicts {
            #expect(HandshakeFailure.verdict(from: error) == nil, "\(error)")
        }
    }

    @Test func anAlertDuringTheHandshakeIsNeverTheJournalsVerdict() {
        // proto/session.md § 7: an alert before the client confirmed the journal and sent its
        // Finished is not authenticated. Falsified by trusting a pre-window access denied, which
        // would let anyone on the path unpair the device with one forged alert.
        for status in [PeerAlert.accessDenied, PeerAlert.certificateUnknown, PeerAlert.internalError] {
            let dialError = innerTLSError(for: NWError.tls(status))
            let mapped = RaceCoordinator<Int>.sessionError(from: dialError)
            #expect(mapped.attemptFailureClass == .tls, "status \(status)")
            #expect(RaceCoordinator<Int>.isVerdict(mapped) == false, "status \(status)")
            let raw = RaceCoordinator<Int>.sessionError(from: NWError.tls(status))
            #expect(raw == .unreachable, "status \(status)")
        }
    }

    @Test func unknownJournalMapsToItsOwnOutcome() {
        // Falsified by folding a peer that is not the paired journal into a generic TLS failure.
        #expect(RaceCoordinator<Int>.sessionError(from: InnerTLSError.unknownJournal(claimedJournalID: "j")) == .unknownJournal)
        #expect(RaceCoordinator<Int>.sessionError(from: InnerTLSError.unknownJournal(claimedJournalID: nil)) == .unknownJournal)
    }

    @Test func directConnectFailuresBeforeTLSDoNotReadAsTLS() {
        // A direct address that refuses or never answers has not proved anything about the peer.
        for error in [NWError.posix(.ECONNREFUSED), NWError.posix(.ECONNRESET), NWError.posix(.ECONNABORTED)] {
            let mapped = RaceCoordinator<Int>.sessionError(from: innerTLSError(for: error))
            #expect(mapped == .transportFailed("connect refused"))
            #expect(mapped.attemptFailureClass == .transport)
        }
        for error in [
            NWError.posix(.EHOSTUNREACH),
            NWError.posix(.ENETUNREACH),
            NWError.posix(.ETIMEDOUT),
            NWError.dns(-65554),
        ] {
            let mapped = RaceCoordinator<Int>.sessionError(from: innerTLSError(for: error))
            #expect(mapped == .unreachable)
            #expect(mapped.attemptFailureClass == .unreachable)
        }
        let tls = RaceCoordinator<Int>.sessionError(from: innerTLSError(for: NWError.tls(-9800)))
        #expect(tls.attemptFailureClass == .tls)
    }

    @Test func otherDialErrorMapsToUnreachable() {
        // Other dial errors must fall back to unreachable session errors.
        #expect(RaceCoordinator<Int>.sessionError(from: DialError.connectTimeout) == .unreachable)
    }

    @Test func aggregateFailurePrecedence() {
        // A verdict short-circuits before aggregation; aggregate preserves remaining precedence.
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
        // An unknown journal outranks a leg that did not answer, and yields to the relay's own rejection.
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawNotEntitled: false,
            sawAuthRefreshRequired: false,
            sawUnknownJournal: true
        ) == .unknownJournal)
        #expect(RaceCoordinator<Int>.aggregateFailure(
            sawNotEntitled: false,
            sawAuthRefreshRequired: true,
            sawUnknownJournal: true
        ) == .authRefreshRequired)
    }
}
