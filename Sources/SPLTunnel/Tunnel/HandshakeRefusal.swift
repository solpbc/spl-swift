// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Network
import os
import Security

private let refusalLog = SPLLogging.logger(for: .session)

/// The client's rule for a journal that refuses the inner TLS handshake
/// (`proto/session.md` § 7, "inner TLS handshake").
///
/// Access denied (49) means the device is unpaired, so the credential stops at once.
/// Certificate unknown (46) means the journal could not read its device list, so the
/// client retries and keeps the credential. Any other refusal retries until refusals
/// have gone on long enough, then stops as unpaired. A journal that was never reached,
/// or a peer that is not the paired journal, is not refusing anything and never counts.
public enum HandshakeRefusalPolicy {
    /// Counted refusals that stop a credential with ``HandshakeStop/refusalsExhausted``.
    public static let refusalLimit = 7

    /// Minimum spacing between two counted refusals.
    ///
    /// Refusals closer together than this count once, so a burst of retries cannot
    /// reach the limit: a credential stops only after refusals have continued for at
    /// least `(refusalLimit - 1) * refusalSpacing`. Time without attempts, or with the
    /// journal unreachable, never advances the count.
    public static let refusalSpacing: Duration = .seconds(300)
}

/// Why a client stopped dialling a credential. Both present the unpaired state.
///
/// A stop ends the credential, never the caller's data: keep anything still waiting
/// to be delivered and deliver it after the next pairing. Only a new pairing (a new
/// client credential) ends a stop; the journal accepting a connection does not.
public enum HandshakeStop: String, Codable, Sendable, Equatable {
    /// The journal refused this device with access denied (49).
    case accessDenied
    /// Refusals other than access denied and certificate unknown reached
    /// ``HandshakeRefusalPolicy/refusalLimit``.
    case refusalsExhausted

    /// The error a stopped client reports instead of dialling.
    var sessionError: SessionError {
        switch self {
        case .accessDenied:
            .revoked
        case .refusalsExhausted:
            .refusalsExhausted
        }
    }
}

/// How one connection to the journal ended, for the refusal count.
enum HandshakeFailure: Sendable, Equatable {
    /// The journal was not reached or did not answer: no route, a timeout, a reset, a
    /// close, a locally detected TLS failure, an alert before the verdict window, the
    /// relay's own rejection or a failure of its outer connection. Never counted.
    case unreachable
    /// The journal refused this device with access denied (49). Stops.
    case accessDenied
    /// The journal could not read its device list (46). Retry; neither counts nor clears.
    case certificateUnknown
    /// The journal refused the handshake with any other received alert. Counted.
    case refused
    /// A peer that is not the paired journal answered. Never counts, clears or stops.
    case unknownJournal

    /// The session error a connection that ended this way inside its verdict window reports.
    var sessionError: SessionError {
        switch self {
        case .unreachable:
            .unreachable
        case .accessDenied:
            .revoked
        case .certificateUnknown:
            .certificateUnknown
        case .refused:
            .refused
        case .unknownJournal:
            .unknownJournal
        }
    }

    /// The journal's verdict carried by a failed read or write on an established inner
    /// TLS connection, or `nil` when the failure is not a received alert.
    ///
    /// Only an alert the peer sent is a verdict. On Apple platforms that arrives as an
    /// `errSSLPeer*` status, or as the generic received-fatal-alert status. Every
    /// received alert other than access denied (49) and certificate unknown (46) is
    /// counted, including record-layer alerts and codes this client does not recognise.
    /// Anything else (a graceful or silent close, a reset, a local record or decrypt
    /// failure) is not a verdict.
    static func verdict(from error: any Error) -> HandshakeFailure? {
        let status: OSStatus
        if let alert = error as? TLSPeerAlert {
            status = alert.status
        } else if let networkError = error as? NWError, case .tls(let tlsStatus) = networkError {
            status = tlsStatus
        } else {
            return nil
        }
        guard isReceivedAlert(status) else {
            return nil
        }
        switch status {
        case errSSLPeerAccessDenied:
            return .accessDenied
        case errSSLPeerCertUnknown:
            return .certificateUnknown
        default:
            return .refused
        }
    }

    static func isReceivedAlert(_ status: OSStatus) -> Bool {
        if status == errSSLFatalAlert {
            return true
        }
        // why: Security/SecureTransport.h assigns the received alerts one contiguous range in
        // alert order, errSSLIllegalParam (illegal_parameter, 47) included. A record failure
        // this client detects itself (errSSLBadRecordMac, errSSLDecryptionFail) sits outside it.
        return (errSSLPeerNoRenegotiation...errSSLPeerUnexpectedMsg).contains(status)
    }
}

/// A fatal alert the peer sent, read or written on an established inner TLS connection.
struct TLSPeerAlert: Error, Equatable, Sendable {
    let status: OSStatus
}

/// The persisted refusal state for one client credential.
public struct HandshakeRefusalRecord: Codable, Sendable, Equatable {
    /// Refusals counted since the journal last accepted this credential.
    public var refusals: Int
    /// The wall-clock time of the last counted refusal.
    public var lastCountedAt: Date?
    /// Why this credential stopped, if it has.
    public var stop: HandshakeStop?

    public init(refusals: Int = 0, lastCountedAt: Date? = nil, stop: HandshakeStop? = nil) {
        self.refusals = refusals
        self.lastCountedAt = lastCountedAt
        self.stop = stop
    }
}

/// Where a client keeps the refusal record of each credential, so the count and the
/// stop survive the process.
///
/// The record is keyed on the client credential (its certificate fingerprint) and kept
/// apart from the pairing record, so a new pairing starts fresh. Every update to a record
/// is a read, then a write of the result.
/// A store keeps the record's dates exactly: within a process the ledger recognises the
/// refusal it last counted by its stored time, to measure spacing on the monotonic clock.
public protocol HandshakeRefusalStore: Sendable {
    /// The record for a credential: `nil` when none exists. Throws when the record
    /// could not be read, which is never treated as "none".
    func loadRefusalRecord(credential: String) throws -> HandshakeRefusalRecord?

    /// Replaces the record for a credential. Throws when it could not be written.
    func saveRefusalRecord(_ record: HandshakeRefusalRecord, credential: String) throws
}

public enum HandshakeRefusalStoreError: Error, Equatable, Sendable {
    case loadFailed(status: OSStatus)
    case saveFailed(status: OSStatus)
    case decodingFailed
    case encodingFailed
}

/// The production refusal store: a Keychain item per credential, next to the pairing.
///
/// It uses the pairing's service, access group, keychain and accessibility under an
/// account of its own, so any launch that can read the pairing can read the refusal
/// record, and no code that rewrites the pairing touches it.
public struct SPLKeychainRefusalStore: HandshakeRefusalStore {
    public let pairingPolicy: KeychainPolicy

    public init(pairingPolicy: KeychainPolicy) {
        self.pairingPolicy = pairingPolicy
    }

    public func loadRefusalRecord(credential: String) throws -> HandshakeRefusalRecord? {
        var query = recordPolicy(credential: credential).baseQuery()
        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw HandshakeRefusalStoreError.loadFailed(status: errSecInternalError)
            }
            return try Self.decode(data)
        case errSecItemNotFound:
            return nil
        default:
            throw HandshakeRefusalStoreError.loadFailed(status: status)
        }
    }

    public func saveRefusalRecord(_ record: HandshakeRefusalRecord, credential: String) throws {
        let data = try Self.encode(record)
        let policy = recordPolicy(credential: credential)
        let status = SecItemAdd(policy.addAttributes(data: data) as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            let updateStatus = SecItemUpdate(
                policy.baseQuery() as CFDictionary,
                policy.updateAttributes(data: data) as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw HandshakeRefusalStoreError.saveFailed(status: updateStatus)
            }
        default:
            throw HandshakeRefusalStoreError.saveFailed(status: status)
        }
    }

    // why: dates are stored as the exact Date value; a format that rounds them (ISO 8601 drops
    // fractional seconds) would never match the ledger's in-process anchor again.
    static func encode(_ record: HandshakeRefusalRecord) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .deferredToDate
        do {
            return try encoder.encode(record)
        } catch {
            throw HandshakeRefusalStoreError.encodingFailed
        }
    }

    static func decode(_ data: Data) throws -> HandshakeRefusalRecord {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .deferredToDate
        do {
            return try decoder.decode(HandshakeRefusalRecord.self, from: data)
        } catch {
            throw HandshakeRefusalStoreError.decodingFailed
        }
    }

    func recordPolicy(credential: String) -> KeychainPolicy {
        KeychainPolicy(
            service: pairingPolicy.service,
            account: "spl-handshake-refusals.\(credential)",
            accessGroup: pairingPolicy.accessGroup,
            useDataProtectionKeychain: pairingPolicy.useDataProtectionKeychain,
            accessibility: pairingPolicy.accessibility
        )
    }
}

extension SPLKeychainStore {
    /// The refusal store that sits next to this pairing store, with the same accessibility.
    public var refusalStore: SPLKeychainRefusalStore {
        SPLKeychainRefusalStore(pairingPolicy: policy)
    }
}

extension StoredPairing {
    /// The key of this pairing's refusal record: the SHA-256 of the client certificate.
    var refusalCredential: String {
        if let leaf = try? CertChain.certificates(fromPEM: clientCertPEM).first {
            return CertChain.sha256Fingerprint(of: leaf)
        }
        // why: a pairing whose certificate does not parse can never complete a handshake;
        // its text still names the credential uniquely.
        return CertChain.hex(SHA256.hash(data: Data(clientCertPEM.utf8)))
    }
}

/// An in-process store with no persistence, the internal default for test seams.
final class EphemeralRefusalStore: HandshakeRefusalStore, @unchecked Sendable {
    // why: store calls are synchronous and may come from any ledger; NSLock guards the map.
    private let lock = NSLock()
    private var records: [String: HandshakeRefusalRecord] = [:]

    func loadRefusalRecord(credential: String) throws -> HandshakeRefusalRecord? {
        lock.withLock { records[credential] }
    }

    func saveRefusalRecord(_ record: HandshakeRefusalRecord, credential: String) throws {
        lock.withLock { records[credential] = record }
    }
}

/// The refusal state of one credential: the count, the spacing and the stop.
///
/// Every connection of the credential reports how it ended. The ledger keeps the record
/// in the store, so the count and the stop persist across processes. Within a process,
/// spacing uses a monotonic clock; across processes, the persisted wall-clock time. When
/// the store cannot be read, events are kept in order and replayed against the stored
/// record on the next good read, never written over a record that was not read, and an
/// access denied still stops this process at once.
actor HandshakeRefusalLedger {
    struct Clock: Sendable {
        let wall: @Sendable () -> Date
        let monotonic: @Sendable () -> ContinuousClock.Instant

        static let system = Clock(wall: { Date() }, monotonic: { .now })
    }

    private enum Event: Sendable {
        case accepted
        case accessDenied
        case refused(wall: Date, instant: ContinuousClock.Instant)
    }

    /// The last refusal this process counted: its persisted wall time and its monotonic
    /// instant. While the record still names that wall time, spacing is measured on the
    /// monotonic clock.
    private struct Anchor: Sendable {
        let wall: Date
        let instant: ContinuousClock.Instant
    }

    // why: one process may run several ledgers for a credential; every read-then-write of
    // a record holds this lock so their updates are serialised.
    private static let storeLock = NSLock()

    let credential: String
    private let store: any HandshakeRefusalStore
    private let clock: Clock
    private var persisted = HandshakeRefusalRecord()
    private var anchor: Anchor?
    private var pending: [Event] = []
    private var latched: HandshakeStop?
    private(set) var lastStoreFailure: (any Error)?

    init(credential: String, store: any HandshakeRefusalStore, clock: Clock = .system) {
        self.credential = credential
        self.store = store
        self.clock = clock
    }

    /// Why this credential stopped, if it has, reading the store first.
    func stop() -> HandshakeStop? {
        if let latched {
            return latched
        }
        synchronize()
        return latchFromView()
    }

    /// The journal sent its first application byte on a connection. Clears the count,
    /// never a stop.
    func accepted() {
        pending.append(.accepted)
        synchronize()
    }

    /// Records how a connection that the journal did not accept ended, and returns the
    /// credential's stop, if any.
    @discardableResult
    func record(_ failure: HandshakeFailure) -> HandshakeStop? {
        switch failure {
        case .accessDenied:
            if latched == nil {
                latched = .accessDenied
            }
            pending.append(.accessDenied)
        case .refused:
            pending.append(.refused(wall: clock.wall(), instant: clock.monotonic()))
        case .unreachable, .certificateUnknown, .unknownJournal:
            return stop()
        }
        synchronize()
        return latchFromView()
    }

    /// Stops this credential in this process without recording a new event.
    func latch(_ stop: HandshakeStop) {
        if latched == nil {
            latched = stop
        }
    }

    /// The record as this process sees it: the last good read with every event not yet
    /// written applied on top.
    func view() -> HandshakeRefusalRecord {
        var record = persisted
        var anchor = anchor
        for event in pending {
            Self.apply(event, to: &record, anchor: &anchor)
        }
        return record
    }

    private func latchFromView() -> HandshakeStop? {
        if latched == nil, let stop = view().stop {
            latched = stop
        }
        return latched
    }

    private func synchronize() {
        Self.storeLock.withLock {
            let stored: HandshakeRefusalRecord
            do {
                stored = try store.loadRefusalRecord(credential: credential) ?? HandshakeRefusalRecord()
            } catch {
                lastStoreFailure = error
                refusalLog.error("refusal record read failed pending=\(self.pending.count, privacy: .public)")
                return
            }
            var record = stored
            var anchor = anchor
            for event in pending {
                Self.apply(event, to: &record, anchor: &anchor)
            }
            if record != stored {
                do {
                    try store.saveRefusalRecord(record, credential: credential)
                } catch {
                    lastStoreFailure = error
                    persisted = stored
                    refusalLog.error("refusal record write failed pending=\(self.pending.count, privacy: .public)")
                    return
                }
            }
            if record.refusals != stored.refusals || record.stop != stored.stop {
                refusalLog.notice("refusal record refusals=\(record.refusals, privacy: .public) stop=\(record.stop?.rawValue ?? "none", privacy: .public)")
            }
            pending.removeAll()
            persisted = record
            self.anchor = anchor
            lastStoreFailure = nil
        }
    }

    private static func apply(_ event: Event, to record: inout HandshakeRefusalRecord, anchor: inout Anchor?) {
        switch event {
        case .accepted:
            record.refusals = 0
            record.lastCountedAt = nil
            anchor = nil
        case .accessDenied:
            if record.stop == nil {
                record.stop = .accessDenied
            }
        case .refused(let wall, let instant):
            guard counts(wall: wall, instant: instant, record: record, anchor: anchor) else {
                return
            }
            record.refusals = min(record.refusals, Int.max - 1) + 1
            record.lastCountedAt = wall
            anchor = Anchor(wall: wall, instant: instant)
            if record.refusals >= HandshakeRefusalPolicy.refusalLimit, record.stop == nil {
                record.stop = .refusalsExhausted
            }
        }
    }

    private static func counts(
        wall: Date,
        instant: ContinuousClock.Instant,
        record: HandshakeRefusalRecord,
        anchor: Anchor?
    ) -> Bool {
        guard let last = record.lastCountedAt else {
            return true
        }
        if let anchor, anchor.wall == last {
            return anchor.instant.duration(to: instant) >= HandshakeRefusalPolicy.refusalSpacing
        }
        // A stored time later than now means the clock moved back: count, and store now.
        guard last <= wall else {
            return true
        }
        let spacing = HandshakeRefusalPolicy.refusalSpacing.components
        let spacingSeconds = Double(spacing.seconds) + Double(spacing.attoseconds) / 1e18
        return wall.timeIntervalSince(last) >= spacingSeconds
    }
}
