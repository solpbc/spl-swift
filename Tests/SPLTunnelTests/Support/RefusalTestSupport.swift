// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
@testable import SPLTunnel

struct TestRefusalStoreError: Error, Equatable {}

/// An in-memory refusal store whose reads and writes can be made to fail.
final class TestRefusalStore: HandshakeRefusalStore, @unchecked Sendable {
    // why: store calls are synchronous from ledger actors and test tasks; NSLock guards state.
    private let lock = NSLock()
    private var records: [String: HandshakeRefusalRecord] = [:]
    private var failingReads = false
    private var failingWrites = false
    private var reads = 0
    private var writes = 0

    func loadRefusalRecord(credential: String) throws -> HandshakeRefusalRecord? {
        try lock.withLock {
            reads += 1
            if failingReads {
                throw TestRefusalStoreError()
            }
            return records[credential]
        }
    }

    func saveRefusalRecord(_ record: HandshakeRefusalRecord, credential: String) throws {
        try lock.withLock {
            if failingWrites {
                throw TestRefusalStoreError()
            }
            writes += 1
            records[credential] = record
        }
    }

    func seed(_ record: HandshakeRefusalRecord, credential: String) {
        lock.withLock { records[credential] = record }
    }

    func record(credential: String) -> HandshakeRefusalRecord? {
        lock.withLock { records[credential] }
    }

    func setFailingReads(_ failing: Bool) {
        lock.withLock { failingReads = failing }
    }

    func setFailingWrites(_ failing: Bool) {
        lock.withLock { failingWrites = failing }
    }

    var readCount: Int {
        lock.withLock { reads }
    }

    var writeCount: Int {
        lock.withLock { writes }
    }
}

/// A wall clock and a monotonic clock that move only when a test moves them.
final class ManualRefusalClock: @unchecked Sendable {
    // why: ledger actors read the clock while test tasks advance it; NSLock guards both values.
    private let lock = NSLock()
    private var wall: Date
    private var instant: ContinuousClock.Instant

    init(wall: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        self.wall = wall
        self.instant = .now
    }

    /// Time passes: both clocks move.
    func advance(_ duration: Duration) {
        lock.withLock {
            instant = instant.advanced(by: duration)
            wall = wall.addingTimeInterval(duration.refusalTestInterval)
        }
    }

    /// The wall clock is set, as a user or a network time correction does; the monotonic
    /// clock does not move.
    func setWall(_ date: Date) {
        lock.withLock { wall = date }
    }

    var now: Date {
        lock.withLock { wall }
    }

    var clock: HandshakeRefusalLedger.Clock {
        HandshakeRefusalLedger.Clock(
            wall: { self.lock.withLock { self.wall } },
            monotonic: { self.lock.withLock { self.instant } }
        )
    }
}

extension Duration {
    var refusalTestInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }
}

func refusalLedger(
    for pairing: StoredPairing,
    store: TestRefusalStore,
    clock: ManualRefusalClock? = nil
) -> HandshakeRefusalLedger {
    HandshakeRefusalLedger(
        credential: pairing.refusalCredential,
        store: store,
        clock: clock?.clock ?? .system
    )
}

/// The status of a received alert, by TLS alert code, as Network.framework reports it.
enum PeerAlert {
    static let accessDenied: Int32 = -9832
    static let certificateUnknown: Int32 = -9829
    static let internalError: Int32 = -9838
    static let badCertificate: Int32 = -9825
    static let unexpectedMessage: Int32 = -9819
    static let badRecordMac: Int32 = -9820
    static let recordOverflow: Int32 = -9822
    static let genericFatal: Int32 = -9802
    static let closedGraceful: Int32 = -9805
    static let closedAbort: Int32 = -9806
    static let closedNoNotify: Int32 = -9816
    static let localDecryptionFailure: Int32 = -9845
    static let localBadRecordMac: Int32 = -9846
}
