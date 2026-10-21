// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Testing
@testable import SPLTunnel

private let realStackClientInfo = SPLClientInfo(userAgent: "spl-swift-refusal-real-stack/1")
private let realStackRuns = 50

/// proto/session.md § 7 on the real Network.framework TLS 1.3 stack, against in-process
/// loopback servers.
@Suite(
    "RefusalRuleRealStack",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct RefusalRuleRealStackTests {
    // A TLS 1.3 server checks the client certificate after the client's Finished, so its
    // refusal must land inside the verdict window on every run. Falsified by a client that
    // reports ready only after reading past the server's verdict, or that fails the handshake
    // before ready, either of which would make the journal's refusal untrusted and uncounted.
    @Test func aServerRejectingTheClientCertificateLandsInsideTheVerdictWindowEveryRun() async throws {
        var inWindow: [String: Int] = [:]
        var beforeWindow: [String] = []
        var withoutVerdict: [String] = []
        for run in 0..<realStackRuns {
            let fixture = try TestCA.make()
            let server = TLSEchoServer(bundle: fixture, rejectClientCertificate: true)
            try await server.start()
            let store = TestRefusalStore()
            let session = TunnelSession(pairing: fixture.pairing, clientInfo: realStackClientInfo, refusalStore: store)
            let states = await stateProbe(for: session)
            let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: await server.port, scope: "loopback")

            var verdict: SessionError?
            do {
                _ = try await session.connect(endpoints: [endpoint])
                if await waitForFailure(in: states, timeout: .seconds(5), matching: { RaceCoordinator<Int>.isVerdict($0) }) {
                    verdict = await states.firstFailure(matching: { RaceCoordinator<Int>.isVerdict($0) })
                } else {
                    withoutVerdict.append("run \(run)")
                }
            } catch let error as SessionError where RaceCoordinator<Int>.isVerdict(error) {
                verdict = error
            } catch {
                beforeWindow.append("run \(run): \(error)")
            }
            if let verdict {
                inWindow[TunnelStateLogDescription.describe(verdict), default: 0] += 1
                let record = store.record(credential: fixture.pairing.refusalCredential)
                #expect(record?.refusals == (verdict == .refused ? 1 : 0), "run \(run)")
            }
            await session.disconnect()
            await states.stop()
            await server.stop()
        }
        print("refusal-real-stack verdict-window in_window=\(inWindow) before_window=\(beforeWindow.count) without_verdict=\(withoutVerdict.count)")
        #expect(beforeWindow.isEmpty, "\(beforeWindow.count) of \(realStackRuns) runs failed before the verdict window: \(beforeWindow)")
        #expect(withoutVerdict.isEmpty, "\(withoutVerdict.count) of \(realStackRuns) runs ended without a verdict: \(withoutVerdict)")
        #expect(inWindow.values.reduce(0, +) == realStackRuns)
    }

    enum NegativeTwin: String, CaseIterable, Sendable {
        case closeNotify
        case finWithoutCloseNotify
        case reset
    }

    // The negative twin. Falsified by counting a close or a reset that ends the connection
    // after the handshake and before the journal's first byte: it is not a refusal.
    @Test(arguments: NegativeTwin.allCases)
    func aServerThatEndsTheConnectionAfterTheHandshakeIsUnreachableAndNeverCounts(_ twin: NegativeTwin) async throws {
        var endings: [String: Int] = [:]
        for run in 0..<realStackRuns {
            let fixture = try TestCA.make()
            let server = TLSEchoServer(
                bundle: fixture,
                mode: twin == .closeNotify ? .closeAfterHandshake : .silentAfterHandshake
            )
            try await server.start()
            var proxy: HandshakeDropProxy?
            var port = await server.port
            switch twin {
            case .closeNotify:
                break
            case .finWithoutCloseNotify, .reset:
                let dropping = HandshakeDropProxy(
                    upstreamPort: port,
                    handshakes: server.completedHandshakes,
                    drop: twin == .reset ? .reset : .finWithoutCloseNotify
                )
                try await dropping.start()
                port = await dropping.port
                proxy = dropping
            }
            let store = TestRefusalStore()
            let session = TunnelSession(
                pairing: fixture.pairing,
                clientInfo: realStackClientInfo,
                policy: SessionPolicy(keepalive: KeepalivePolicy(interval: .seconds(30))),
                refusalStore: store
            )
            let states = await stateProbe(for: session)
            let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: port, scope: "loopback")

            var ending: SessionError?
            do {
                _ = try await session.connect(endpoints: [endpoint])
                if await waitForFailure(in: states, timeout: .seconds(5), matching: { _ in true }) {
                    ending = await states.firstFailure(matching: { _ in true })
                }
            } catch let error as SessionError {
                ending = error
            }
            if let ending {
                endings[Self.describe(ending), default: 0] += 1
                #expect(RaceCoordinator<Int>.isVerdict(ending) == false, "run \(run): \(ending)")
                #expect(ending != .unknownJournal, "run \(run)")
            } else {
                Issue.record("run \(run) neither failed nor connected")
            }
            #expect((store.record(credential: fixture.pairing.refusalCredential) ?? HandshakeRefusalRecord()) == HandshakeRefusalRecord(), "run \(run)")
            await session.disconnect()
            await states.stop()
            await proxy?.stop()
            await server.stop()
        }
        print("refusal-real-stack negative-twin mode=\(twin.rawValue) endings=\(endings)")
    }

    // An attacker on the path cannot forge the journal's alert after the handshake, but it can
    // corrupt a record. The client detects that itself, so it is not the journal's verdict.
    // Falsified by a classifier that counts a locally detected record failure (a bad record MAC
    // or a decrypt failure) as a received alert: anyone on the path could unpair the owner.
    @Test func aRecordTamperedWithOnThePathIsUnreachableAndNeverCounts() async throws {
        var endings: [String: Int] = [:]
        for run in 0..<realStackRuns {
            let fixture = try TestCA.make()
            let server = TLSEchoServer(bundle: fixture, mode: .mux)
            try await server.start()
            let proxy = RecordTamperProxy(upstreamPort: await server.port)
            try await proxy.start()
            let store = TestRefusalStore()
            let session = TunnelSession(pairing: fixture.pairing, clientInfo: realStackClientInfo, refusalStore: store)
            let states = await stateProbe(for: session)
            let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: await proxy.port, scope: "loopback")

            var ending: SessionError?
            do {
                _ = try await session.connect(endpoints: [endpoint])
                if await waitForFailure(in: states, timeout: .seconds(5), matching: { _ in true }) {
                    ending = await states.firstFailure(matching: { _ in true })
                }
            } catch let error as SessionError {
                ending = error
            }
            if let ending {
                endings[Self.describe(ending), default: 0] += 1
                #expect(RaceCoordinator<Int>.isVerdict(ending) == false, "run \(run): \(ending)")
            } else {
                Issue.record("run \(run) neither failed nor connected")
            }
            #expect((store.record(credential: fixture.pairing.refusalCredential) ?? HandshakeRefusalRecord()) == HandshakeRefusalRecord(), "run \(run)")
            await session.disconnect()
            await states.stop()
            await proxy.stop()
            await server.stop()
        }
        print("refusal-real-stack tampered-record endings=\(endings)")
    }

    // Falsified by reporting an unpinned CA as a generic TLS failure, or by naming no claim.
    @Test func aServerPresentingAnUnpinnedCAIsAnUnknownJournalClaimingThatCAsID() async throws {
        let fixture = try TestCA.make()
        let stranger = try TestCA.make()
        let server = TLSEchoServer(bundle: stranger, clientCAPEM: fixture.caCertificatePEM)
        try await server.start()
        await expectInnerTLSError(.unknownJournal(claimedJournalID: try TestCA.journalID(of: stranger))) {
            _ = try await InnerTLS.connectLAN(host: "127.0.0.1", port: await server.port, pairing: fixture.pairing)
        }
        await server.stop()
    }

    // Falsified by trusting a chain because it carries the pinned CA, or by naming the other
    // CA as the claim when the peer presented the paired journal's own CA.
    @Test func thePairedCAWithoutALeafItSignedIsAnUnknownJournalWithNoClaim() async throws {
        let fixture = try TestCA.make()
        let stranger = try TestCA.make()
        let identity = try TestCA.serverIdentity(signedBy: stranger, presentedCAPEM: fixture.caCertificatePEM)
        let server = TLSEchoServer(bundle: fixture, identity: identity)
        try await server.start()
        await expectInnerTLSError(.unknownJournal(claimedJournalID: nil)) {
            _ = try await InnerTLS.connectLAN(host: "127.0.0.1", port: await server.port, pairing: fixture.pairing)
        }
        await server.stop()
    }

    // proto/session.md § 7: a chain to the pinned CA that fails another check is the paired
    // journal failing an ordinary handshake. Falsified by reporting it as an unknown journal,
    // which would tell the owner something else answered when their own journal's clock or
    // certificate is wrong.
    @Test func aChainToThePinnedCAThatFailsItsDatesIsNotAnUnknownJournal() async throws {
        let fixture = try TestCA.make()
        let expired = try TestCA.serverIdentity(
            signedBy: fixture,
            notBefore: Date(timeIntervalSinceNow: -2 * 86_400),
            notAfter: Date(timeIntervalSinceNow: -86_400)
        )
        let server = TLSEchoServer(bundle: fixture, identity: expired)
        try await server.start()
        let port = await server.port
        do {
            _ = try await InnerTLS.connectLAN(host: "127.0.0.1", port: port, pairing: fixture.pairing)
            Issue.record("an expired journal certificate must not verify")
        } catch let error as InnerTLSError {
            guard case .handshakeFailed = error else {
                Issue.record("expected an ordinary handshake failure, got \(error)")
                return
            }
        }

        let session = TunnelSession(pairing: fixture.pairing, clientInfo: realStackClientInfo, refusalStore: TestRefusalStore())
        let sightings = session.unknownJournalSightings
        do {
            _ = try await session.connect(endpoints: [.lan(host: "127.0.0.1", port: port, scope: "loopback")])
            Issue.record("expected the connection to fail")
        } catch let error as SessionError {
            #expect(error.attemptFailureClass == .tls)
        }
        await session.disconnect()
        var seen = 0
        for await _ in sightings {
            seen += 1
        }
        #expect(seen == 0)
        await server.stop()
    }

    // Falsified by letting an unknown journal end the attempt or block the relay, or by
    // dropping the sighting because another leg connected.
    @Test func aLANUnknownJournalWithAWorkingRelayConnectsThroughTheRelayAndDeliversTheSighting() async throws {
        let fixture = try TestCA.make()
        let stranger = try TestCA.make()
        let lanServer = TLSEchoServer(bundle: stranger, clientCAPEM: fixture.caCertificatePEM)
        try await lanServer.start()
        let lanPort = await lanServer.port
        let journal = TLSEchoServer(bundle: fixture, mode: .mux)
        try await journal.start()
        let relay = RelayBridgeServer(tlsPort: await journal.port)
        try await relay.start()
        let relayURL = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let session = tunnelSessionAllowingPlaintextRelay(pairing: fixture.pairing, clientInfo: realStackClientInfo)
        let sightings = session.unknownJournalSightings
        let attempts = session.attemptUpdates

        let via = try await session.connect(endpoints: [
            .lan(host: "127.0.0.1", port: lanPort, scope: "loopback"),
            .relay(endpoint: relayURL, instanceID: fixture.pairing.instanceID, deviceToken: "test-token"),
        ])
        #expect(via == .relay(endpoint: relayURL))
        let stream = try await session.openStream()
        try await stream.write(Data([0x0a, 0x0b]))
        #expect(try await readInboundPayload(from: stream, timeout: .seconds(2)) == Data([0x0a, 0x0b]))

        var iterator = sightings.makeAsyncIterator()
        let sighting = await iterator.next()
        #expect(sighting == UnknownJournalSighting(
            dialled: .lanDirect(host: "127.0.0.1", port: lanPort),
            claimedJournalID: try TestCA.journalID(of: stranger)
        ))
        var failureClasses: [TunnelAttemptFailureClass] = []
        for await event in attempts {
            if case .failed(let failureClass, _) = event.phase {
                failureClasses.append(failureClass)
            }
        }
        #expect(failureClasses == [.unknownJournal])

        await session.disconnect()
        await relay.stop()
        await journal.stop()
        await lanServer.stop()
    }

    enum RelayEnding: String, CaseIterable, Sendable {
        /// The relay leg stops taking writes while the journal's refusal is still on its way.
        case writeFailsBeforeTheRefusalArrives
        /// The relay leg closes abnormally just after delivering the journal's refusal.
        case webSocketFailsJustAfterTheRefusal
        /// The relay leg stops taking writes and then delivers nothing more until it is closed.
        case writeFailsAndTheRelayGoesQuiet

        static let verdictCases: [RelayEnding] = [.writeFailsBeforeTheRefusalArrives, .webSocketFailsJustAfterTheRefusal]
    }

    // Falsified by a grace that only ends when the relay delivers something: a relay leg that
    // stops taking writes and goes quiet would hold the bridge, and the session, open.
    @Test func aFailedRelayWriteWaitsAtMostTheGraceBeforeClosingTheRelayLeg() async throws {
        let fixture = try TestCA.make()
        let journal = TLSEchoServer(bundle: fixture, rejectClientCertificate: true)
        try await journal.start()
        let transport = try await ScriptedRelayTransport.open(port: await journal.port, ending: .writeFailsAndTheRelayGoesQuiet)
        let tls = try await InnerTLS.connectViaTransport(transport: transport, pairing: fixture.pairing)
        try? await tls.send(Data([0x01]))

        #expect(await waitUntil("the relay leg closes", timeout: .seconds(3)) {
            await transport.closedAt != nil
        })
        if let failed = await transport.sendFailedAt, let closed = await transport.closedAt {
            let waited = failed.duration(to: closed)
            #expect(waited >= .milliseconds(900), "waited \(waited)")
            #expect(waited < .milliseconds(1500), "waited \(waited)")
        } else {
            Issue.record("the relay write never failed")
        }
        await tls.close()
        await journal.stop()
    }

    // Outcome 2. Falsified by a relay bridge that tears down the loopback as soon as the relay
    // leg fails, dropping the journal's alert that the relay still had to deliver: the attempt
    // would read as unreachable instead of a counted refusal.
    @Test(arguments: RelayEnding.verdictCases)
    func theRelayLegKeepsTheJournalsVerdict(_ ending: RelayEnding) async throws {
        let fixture = try TestCA.make()
        let journal = TLSEchoServer(bundle: fixture, rejectClientCertificate: true)
        try await journal.start()
        let journalPort = await journal.port
        let store = TestRefusalStore()
        let session = TunnelSession(
            pairing: fixture.pairing,
            tlsConnector: { _, pairing, _ in
                let transport = try await ScriptedRelayTransport.open(port: journalPort, ending: ending)
                return try await InnerTLS.connectViaTransport(transport: transport, pairing: pairing)
            },
            refusalLedger: refusalLedger(for: fixture.pairing, store: store)
        )
        let states = await stateProbe(for: session)

        var verdict: SessionError?
        do {
            _ = try await session.connect(endpoints: [relayEndpoint()])
            _ = try? await session.openStream()
            if await waitForFailure(in: states, timeout: .seconds(5), matching: { RaceCoordinator<Int>.isVerdict($0) }) {
                verdict = await states.firstFailure(matching: { RaceCoordinator<Int>.isVerdict($0) })
            }
        } catch let error as SessionError where RaceCoordinator<Int>.isVerdict(error) {
            verdict = error
        }
        #expect(verdict == .refused)
        #expect(store.record(credential: fixture.pairing.refusalCredential)?.refusals == 1)
        await session.disconnect()
        await states.stop()
        await journal.stop()
    }

    private static func describe(_ error: SessionError) -> String {
        switch error {
        case .inboundClosed(let fault):
            let fault = fault ?? "eof"
            if let range = fault.range(of: "error -?[0-9]+", options: .regularExpression) {
                return "inboundClosed(\(fault[range]))"
            }
            if let range = fault.range(of: "POSIXErrorCode\\(rawValue: [0-9]+\\)|Code=[0-9]+", options: .regularExpression) {
                return "inboundClosed(\(fault[range]))"
            }
            return "inboundClosed(\(fault.prefix(60)))"
        default:
            return TunnelStateLogDescription.describe(error)
        }
    }

    private func expectInnerTLSError(
        _ expected: InnerTLSError,
        _ operation: @escaping @Sendable () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected \(expected)")
        } catch let error as InnerTLSError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}

extension StateProbe {
    func firstFailure(matching: @Sendable (SessionError) -> Bool) -> SessionError? {
        for state in snapshot() {
            if case .failed(let error) = state, matching(error) {
                return error
            }
        }
        return nil
    }
}

/// A relay leg over a plain TCP connection to a loopback journal, scripted to fail at the
/// moment the journal's refusal is in flight.
private actor ScriptedRelayTransport: ByteTransport {
    nonisolated let transportKind = "relay"

    private let connection: NWConnection
    private let ending: RefusalRuleRealStackTests.RelayEnding
    private var encryptedSends = 0
    private var closed = false
    private var released = false
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []
    private var deliveredAfterHandshake = false
    private(set) var sendFailedAt: ContinuousClock.Instant?
    private(set) var closedAt: ContinuousClock.Instant?

    private init(connection: NWConnection, ending: RefusalRuleRealStackTests.RelayEnding) {
        self.connection = connection
        self.ending = ending
    }

    static func open(port: Int, ending: RefusalRuleRealStackTests.RelayEnding) async throws -> ScriptedRelayTransport {
        let connection = NWConnection(
            host: "127.0.0.1",
            port: try #require(NWEndpoint.Port(rawValue: UInt16(port))),
            using: .tcp
        )
        let ready = AsyncStream<Result<Void, Error>>.makeStream()
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                ready.continuation.yield(.success(()))
            case .failed(let error), .waiting(let error):
                ready.continuation.yield(.failure(error))
            default:
                break
            }
        }
        connection.start(queue: .global())
        var iterator = ready.stream.makeAsyncIterator()
        try await iterator.next()?.get()
        return ScriptedRelayTransport(connection: connection, ending: ending)
    }

    func send(_ data: Data) async throws {
        guard !closed else {
            throw DialError.sendFailed("transport closed")
        }
        if Self.carriesEncryptedRecord(data) {
            encryptedSends += 1
        }
        // The client's second encrypted send is its first write after the handshake.
        if ending != .webSocketFailsJustAfterTheRefusal, encryptedSends >= 2 {
            if sendFailedAt == nil {
                sendFailedAt = .now
            }
            if ending == .writeFailsBeforeTheRefusalArrives {
                Task {
                    try? await Task.sleep(for: .milliseconds(100))
                    self.release()
                }
            }
            throw DialError.sendFailed("relay stopped taking writes")
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func receive() async throws -> Data? {
        guard !closed else {
            return nil
        }
        if ending == .webSocketFailsJustAfterTheRefusal, deliveredAfterHandshake {
            throw DialError.receiveFailed("relay closed abnormally")
        }
        var received = try await receiveFromJournal()
        while let pending = received, pending.isEmpty {
            received = try await receiveFromJournal()
        }
        guard let data = received else {
            return nil
        }
        guard encryptedSends >= 1 else {
            return data
        }
        // Bytes after the client's encrypted flight carry the journal's verdict.
        if ending != .webSocketFailsJustAfterTheRefusal, !released {
            await withCheckedContinuation { continuation in
                releaseWaiters.append(continuation)
            }
        }
        guard !closed else {
            // A relay leg closed by the client drops what it still held.
            return nil
        }
        deliveredAfterHandshake = true
        return data
    }

    func close() async {
        guard !closed else {
            return
        }
        closed = true
        closedAt = .now
        connection.cancel()
        release()
    }

    private func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func receiveFromJournal() async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: isComplete ? nil : Data())
                }
            }
        }
    }

    private static func carriesEncryptedRecord(_ data: Data) -> Bool {
        var index = data.startIndex
        while data.endIndex - index >= 5 {
            if data[index] == 0x17 {
                return true
            }
            let length = Int(data[index + 3]) << 8 | Int(data[index + 4])
            index += 5 + length
        }
        return false
    }
}
