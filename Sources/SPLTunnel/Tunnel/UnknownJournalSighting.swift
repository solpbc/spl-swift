// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

/// A peer that answered where the paired journal was expected, but is not it.
///
/// Seen while dialling: the peer presented a certificate that does not chain to the
/// paired journal's CA. A journal whose CA changed has a new journal ID, so this is how
/// both "a different journal holds this address" and "this journal was reset" look to a
/// client. A sighting is not an error: it never counts as a refusal, never stops the
/// credential, and never ends an attempt early, and it is delivered even when another
/// path then connects. The protocol asks the app to tell the owner where it happened.
public struct UnknownJournalSighting: Sendable, Equatable {
    /// Where the client dialled when the peer answered: a direct address, or the relay.
    public let dialled: ConnectedVia

    /// The journal ID the peer **claims**: the ID of the self-signed P-256 certificate in
    /// the chain it presented. Any peer can present another journal's public CA
    /// certificate, so this is never a proven identity. Show it to the owner next to the
    /// paired journal's ID; never decide anything on it. `nil` when the peer presented no
    /// such certificate, or presented the paired journal's own CA without a certificate
    /// that CA signed.
    public let claimedJournalID: String?

    public init(dialled: ConnectedVia, claimedJournalID: String?) {
        self.dialled = dialled
        self.claimedJournalID = claimedJournalID
    }
}
