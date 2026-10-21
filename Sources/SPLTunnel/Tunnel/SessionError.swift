// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

public enum SessionError: Error, Equatable, Sendable {
    case unreachable
    case tlsFailed(String)
    /// The journal refused this device with access denied (49): it is not paired. The
    /// credential has stopped; present the unpaired state and require a new pairing.
    case revoked
    /// The journal refused this device with an alert other than access denied or
    /// certificate unknown. Retry; refusals like this are counted toward
    /// ``HandshakeRefusalPolicy/refusalLimit``.
    case refused
    /// The journal could not read its device list (certificate unknown, 46). Retry and
    /// keep the credential; this neither counts as a refusal nor clears the count.
    case certificateUnknown
    /// Only a peer that is not the paired journal answered. Retry; this never counts,
    /// clears or stops. Where it answered arrives as an ``UnknownJournalSighting``.
    case unknownJournal
    /// Refusals reached ``HandshakeRefusalPolicy/refusalLimit``. The credential has
    /// stopped; present the unpaired state and require a new pairing.
    case refusalsExhausted
    case authRefreshRequired
    case notEntitled
    case notConnected
    case directKeepaliveMissed
    case relayKeepaliveMissed
    case transportFailed(String)
    case inboundClosed(fault: String?)
}
