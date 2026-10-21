// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Security
import Testing
@testable import SPLTunnel

/// proto/session.md § 7, "inner TLS handshake": the refusal count, its spacing, the stop,
/// and their persistence across processes.
@Suite("HandshakeRefusalLedger")
struct HandshakeRefusalLedgerTests {
    private let credential = "credential-under-test"

    @Test func constantsMatchTheReferenceImplementation() {
        #expect(HandshakeRefusalPolicy.refusalLimit == 7)
        #expect(HandshakeRefusalPolicy.refusalSpacing == .seconds(300))
    }

    // Scenario 1. Falsified by counting every refusal (the burst reaches the limit within one
    // spacing interval), or by counting a refusal 299 s after the last counted one.
    @Test func aBurstCountsOnceEachSpacingStepAddsOneAndTheLimitStops() async {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        let ledger = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)

        for _ in 0..<(HandshakeRefusalPolicy.refusalLimit * 3) {
            #expect(await ledger.record(.refused) == nil)
        }
        #expect(await ledger.view().refusals == 1)

        for counted in 2..<HandshakeRefusalPolicy.refusalLimit {
            clock.advance(.seconds(300))
            #expect(await ledger.record(.refused) == nil)
            #expect(await ledger.view().refusals == counted)
        }

        clock.advance(.seconds(299))
        #expect(await ledger.record(.refused) == nil)
        #expect(await ledger.view().refusals == HandshakeRefusalPolicy.refusalLimit - 1)

        clock.advance(.seconds(1))
        #expect(await ledger.record(.refused) == .refusalsExhausted)
        #expect(await ledger.view().refusals == HandshakeRefusalPolicy.refusalLimit)
        #expect(store.record(credential: credential)?.stop == .refusalsExhausted)

        // A stop never clears, not even when the journal later accepts a connection.
        await ledger.accepted()
        #expect(await ledger.stop() == .refusalsExhausted)
        #expect(store.record(credential: credential)?.stop == .refusalsExhausted)
    }

    // Scenario 2. Falsified by letting 46, an unreachable journal or an unknown journal reset
    // the count (it drops) or advance it (it grows), or by advancing it for time spent offline.
    @Test func unreachableCertificateUnknownAndUnknownJournalNeitherAdvanceNorClear() async {
        let clock = ManualRefusalClock()
        let ledger = HandshakeRefusalLedger(credential: credential, store: TestRefusalStore(), clock: clock.clock)
        await ledger.record(.refused)
        for failure in [HandshakeFailure.unreachable, .certificateUnknown, .unknownJournal] {
            for _ in 0..<(HandshakeRefusalPolicy.refusalLimit * 2) {
                clock.advance(.seconds(300))
                #expect(await ledger.record(failure) == nil)
                #expect(await ledger.view().refusals == 1)
            }
        }
        // Days offline between two refusals still advance the count by exactly one.
        clock.advance(.seconds(48 * 3600))
        #expect(await ledger.record(.refused) == nil)
        #expect(await ledger.view().refusals == 2)
    }

    // Scenario 3. Falsified by never clearing on acceptance (the count stays at 6 and the next
    // refusal stops), or by keeping the spacing after a clear (the next refusal does not count).
    @Test func onlyAcceptanceClearsTheCountAndTheNextRefusalCountsAtOnce() async {
        let clock = ManualRefusalClock()
        let ledger = HandshakeRefusalLedger(credential: credential, store: TestRefusalStore(), clock: clock.clock)
        for _ in 0..<(HandshakeRefusalPolicy.refusalLimit - 1) {
            await ledger.record(.refused)
            clock.advance(.seconds(300))
        }
        #expect(await ledger.view().refusals == HandshakeRefusalPolicy.refusalLimit - 1)

        await ledger.accepted()
        #expect(await ledger.view().refusals == 0)
        #expect(await ledger.view().lastCountedAt == nil)

        #expect(await ledger.record(.refused) == nil)
        #expect(await ledger.view().refusals == 1)
        #expect(await ledger.stop() == nil)
    }

    // Scenario 4. Falsified by counting 46 toward the limit, or by treating 49 as one more
    // counted refusal instead of an immediate stop.
    @Test func certificateUnknownNeverStopsAndAccessDeniedDoes() async {
        let clock = ManualRefusalClock()
        let ledger = HandshakeRefusalLedger(credential: credential, store: TestRefusalStore(), clock: clock.clock)
        for _ in 0..<(HandshakeRefusalPolicy.refusalLimit * 3) {
            clock.advance(.seconds(300))
            #expect(await ledger.record(.certificateUnknown) == nil)
        }
        #expect(await ledger.view().refusals == 0)
        #expect(await ledger.record(.accessDenied) == .accessDenied)
        #expect(await ledger.stop() == .accessDenied)
        #expect(HandshakeStop.accessDenied.sessionError == .revoked)
        #expect(HandshakeStop.refusalsExhausted.sessionError == .refusalsExhausted)
    }

    // Falsified by an in-memory-only count: a new process starts from zero and needs seven
    // more refusals, so the next refusal does not stop.
    @Test func aFreshLedgerOverASeededRecordStopsOnItsNextRefusal() async {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        store.seed(
            HandshakeRefusalRecord(refusals: 6, lastCountedAt: clock.now.addingTimeInterval(-300)),
            credential: credential
        )
        let ledger = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)
        #expect(await ledger.stop() == nil)
        #expect(await ledger.record(.refused) == .refusalsExhausted)
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(
            refusals: 7,
            lastCountedAt: clock.now,
            stop: .refusalsExhausted
        ))
    }

    // Falsified by a stop that lives only in memory: a new process would dial again.
    @Test func aSeededStopStopsAFreshLedgerBeforeAnyEvent() async {
        let store = TestRefusalStore()
        store.seed(HandshakeRefusalRecord(stop: .accessDenied), credential: credential)
        let ledger = HandshakeRefusalLedger(credential: credential, store: store)
        #expect(await ledger.stop() == .accessDenied)
    }

    // The rule's own example. Falsified by writing the in-memory events over a record that
    // could not be read (the stored 5 is lost), or by dropping the events (the count stays 5).
    @Test func aFailedReadKeepsEventsAndReplaysThemInOrderAgainstTheStoredRecord() async {
        let clock = ManualRefusalClock()
        let start = clock.now
        let store = TestRefusalStore()
        store.seed(HandshakeRefusalRecord(refusals: 5, lastCountedAt: start), credential: credential)
        store.setFailingReads(true)
        let ledger = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)

        clock.advance(.seconds(10))
        #expect(await ledger.record(.refused) == nil)
        clock.advance(.seconds(390))
        #expect(await ledger.record(.refused) == nil)
        #expect(store.writeCount == 0)
        #expect(await ledger.lastStoreFailure != nil)

        store.setFailingReads(false)
        #expect(await ledger.stop() == nil)
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(
            refusals: 6,
            lastCountedAt: start.addingTimeInterval(400)
        ))
    }

    // Falsified by letting an unreadable store suppress the stop: an access denied must still
    // stop this process at once, and reach the store on the next good read.
    @Test func aFailedReadStillLetsAccessDeniedStop() async {
        let store = TestRefusalStore()
        store.seed(HandshakeRefusalRecord(refusals: 2), credential: credential)
        store.setFailingReads(true)
        let ledger = HandshakeRefusalLedger(credential: credential, store: store)

        #expect(await ledger.record(.accessDenied) == .accessDenied)
        #expect(await ledger.stop() == .accessDenied)
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(refusals: 2))

        store.setFailingReads(false)
        await ledger.accepted()
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(refusals: 0, stop: .accessDenied))
        #expect(await ledger.stop() == .accessDenied)
    }

    // Falsified by dropping an acceptance seen while the store was unreadable: the stored count
    // would survive it.
    @Test func aFailedReadThenAcceptanceThenAGoodReadStoresZero() async {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        store.seed(HandshakeRefusalRecord(refusals: 4, lastCountedAt: clock.now), credential: credential)
        store.setFailingReads(true)
        let ledger = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)
        await ledger.accepted()
        #expect(store.record(credential: credential)?.refusals == 4)

        store.setFailingReads(false)
        #expect(await ledger.stop() == nil)
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(refusals: 0))
    }

    // Falsified by treating "no record" as a failed read (nothing would ever be written).
    @Test func anAbsentRecordStartsAtZero() async {
        let store = TestRefusalStore()
        let ledger = HandshakeRefusalLedger(credential: credential, store: store)
        #expect(await ledger.stop() == nil)
        #expect(await ledger.view() == HandshakeRefusalRecord())
        await ledger.record(.refused)
        #expect(store.record(credential: credential)?.refusals == 1)
        #expect(await ledger.lastStoreFailure == nil)
    }

    // Falsified by a stored time later than now blocking the count until the wall clock
    // catches up (a clock set back would stall the rule for as long as it was moved).
    @Test func aStoredTimeInTheFutureStillLetsTheNextRefusalCount() async {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        store.seed(
            HandshakeRefusalRecord(refusals: 3, lastCountedAt: clock.now.addingTimeInterval(3600)),
            credential: credential
        )
        let ledger = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)
        await ledger.record(.refused)
        #expect(store.record(credential: credential) == HandshakeRefusalRecord(refusals: 4, lastCountedAt: clock.now))
    }

    // Falsified by measuring spacing within a process on the wall clock: a clock set back a
    // day would block the count, and a clock set forward a day would let a burst count twice.
    @Test func spacingWithinAProcessUsesTheMonotonicClock() async {
        let clock = ManualRefusalClock()
        let ledger = HandshakeRefusalLedger(credential: credential, store: TestRefusalStore(), clock: clock.clock)
        await ledger.record(.refused)

        clock.advance(.seconds(300))
        clock.setWall(clock.now.addingTimeInterval(-86_400))
        await ledger.record(.refused)
        #expect(await ledger.view().refusals == 2)

        clock.advance(.seconds(10))
        clock.setWall(clock.now.addingTimeInterval(86_400 * 2))
        await ledger.record(.refused)
        #expect(await ledger.view().refusals == 2)
    }

    // Falsified by swallowing a failed write: the event would be lost, and the next good write
    // would not carry it.
    @Test func aFailedWriteIsReportedAndKeptForTheNextWrite() async {
        let store = TestRefusalStore()
        store.setFailingWrites(true)
        let ledger = HandshakeRefusalLedger(credential: credential, store: store)
        await ledger.record(.refused)
        #expect(await ledger.lastStoreFailure as? TestRefusalStoreError == TestRefusalStoreError())
        #expect(store.record(credential: credential) == nil)
        #expect(await ledger.view().refusals == 1)

        store.setFailingWrites(false)
        #expect(await ledger.stop() == nil)
        #expect(store.record(credential: credential)?.refusals == 1)
        #expect(await ledger.lastStoreFailure == nil)
    }

    // Falsified by two ledgers of one credential writing over each other's updates.
    @Test func twoLedgersOfOneCredentialShareTheRecord() async {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        let first = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)
        let second = HandshakeRefusalLedger(credential: credential, store: store, clock: clock.clock)
        await first.record(.refused)
        clock.advance(.seconds(300))
        await second.record(.refused)
        clock.advance(.seconds(300))
        await first.record(.refused)
        #expect(store.record(credential: credential)?.refusals == 3)
        await second.record(.accessDenied)
        #expect(await first.stop() == .accessDenied)
    }

    // Falsified by keying the record on anything a new pairing keeps (a new pairing would
    // inherit the old credential's count or stop), or by storing it in the pairing item.
    @Test func theRecordIsKeyedOnTheClientCredentialAndKeptApartFromThePairing() throws {
        let first = try TestCA.make()
        let second = try TestCA.make()
        let firstCredential = first.pairing.refusalCredential
        #expect(firstCredential == (try TestCA.fingerprint(certificatePEM: first.clientCertificatePEM)))
        #expect(firstCredential != second.pairing.refusalCredential)

        let pairingPolicy = KeychainPolicy(
            service: "test.spl.refusal.\(UUID().uuidString)",
            accessGroup: "test.spl.group",
            useDataProtectionKeychain: true,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        let recordPolicy = SPLKeychainStore(policy: pairingPolicy).refusalStore.recordPolicy(credential: firstCredential)
        #expect(recordPolicy.service == pairingPolicy.service)
        #expect(recordPolicy.accessGroup == pairingPolicy.accessGroup)
        #expect(recordPolicy.useDataProtectionKeychain == pairingPolicy.useDataProtectionKeychain)
        #expect(recordPolicy.accessibility == pairingPolicy.accessibility)
        #expect(recordPolicy.account != pairingPolicy.account)
        #expect(recordPolicy.account.hasSuffix(firstCredential))
    }

    @Test(.enabled(if: PlainKeychainCapability.isAvailable, "\(PlainKeychainCapability.reason)"))
    func theKeychainStoreTellsAbsentFromStoredAndLeavesThePairingAlone() throws {
        let fixture = try TestCA.make()
        let pairingStore = SPLKeychainStore(policy: KeychainPolicy(
            service: "test.spl.refusal.\(UUID().uuidString)",
            accessGroup: nil,
            useDataProtectionKeychain: false,
            accessibility: .afterFirstUnlock
        ))
        let refusalStore = pairingStore.refusalStore
        let credential = fixture.pairing.refusalCredential
        defer {
            try? pairingStore.delete()
            SecItemDelete(refusalStore.recordPolicy(credential: credential).baseQuery() as CFDictionary)
        }

        #expect(try refusalStore.loadRefusalRecord(credential: credential) == nil)
        try pairingStore.save(fixture.pairing)
        let record = HandshakeRefusalRecord(refusals: 3, lastCountedAt: Date(timeIntervalSince1970: 1_800_000_000))
        try refusalStore.saveRefusalRecord(record, credential: credential)
        #expect(try refusalStore.loadRefusalRecord(credential: credential) == record)
        let stopped = HandshakeRefusalRecord(refusals: 7, lastCountedAt: record.lastCountedAt, stop: .refusalsExhausted)
        try refusalStore.saveRefusalRecord(stopped, credential: credential)
        #expect(try refusalStore.loadRefusalRecord(credential: credential) == stopped)
        #expect(try pairingStore.load() == fixture.pairing)
    }
}
