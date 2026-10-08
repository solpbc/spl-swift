// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let lanEndpoint = TransportEndpoint.lan(host: "192.168.77.1", port: 17657, scope: "lan")
private let returningPolicy = SessionPolicy(returnsToBetterPath: true)
/// The stability timer's sleep; every other supervisor sleep here is a retry.
private let stabilitySleep = Duration.seconds(60)
private let retrySleep = Duration.milliseconds(1)
private let openFailure = SessionError.transportFailed("OPEN send failed")

/// A recovery raised against one carrier waits out its retry delay. If a better
/// path takes over during that wait, the recovery must not close the carrier
/// that replaced the one it was raised against.
@Suite("A recovery for a carrier a better path replaced is dropped", .serialized)
struct TunnelSupervisorSupersededRecoveryTests {
    @Test("A stream that fails on the old carrier does not close the better carrier that replaced it")
    func oldStreamFailureRecoveryIsDroppedAfterPromotion() async throws {
        let sleeper = SleepProbe()
        let candidateGate = TestSignal()
        let candidateAtEndpoint = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint(), muxClosedAfterSuccessCount: 0, muxClosedError: openFailure),
            .success(lanEndpoint, connectedEndpointSignal: candidateAtEndpoint, connectedEndpointGate: candidateGate),
            .success(relayEndpoint())
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: { try await sleeper.sleep($0) }, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        let relay = try await factory.generation(at: 0)
        await relay.setTransferring(true)

        // Hold the better carrier just before it takes over.
        await supervisor.requestUpgrade()
        await candidateAtEndpoint.wait()
        let lan = try await factory.generation(at: 1)

        // An OPEN on the relay fails with no carrier failure, and the
        // supervisor queues its own recovery, which waits out its retry delay.
        do {
            _ = try await supervisor.openStream()
            Issue.record("the relay's OPEN must fail")
        } catch let error as SessionError {
            #expect(error == openFailure)
        }
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 1)

        await candidateGate.signal()
        await waitUntil("better carrier takes over") { await supervisor.connectionMode == .plDirect }
        #expect(await supervisor.attemptState == .connected)

        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("recovery finishes") { await supervisor.reconnectStatus == nil }
        try await Task.sleep(for: .milliseconds(50))

        #expect(await lan.disconnectCount == 0)
        #expect(await factory.count() == 2)
        #expect(await supervisor.connectionMode == .plDirect)
        #expect(await supervisor.attemptState == .connected)
        _ = try await supervisor.openStream()

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test("A reconnect queued against the old carrier is dropped once a better carrier takes over")
    func queuedReconnectIsDroppedAfterPromotion() async throws {
        let sleeper = SleepProbe()
        let candidateGate = TestSignal()
        let candidateAtEndpoint = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint()),
            .success(lanEndpoint, connectedEndpointSignal: candidateAtEndpoint, connectedEndpointGate: candidateGate),
            .success(relayEndpoint())
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: { try await sleeper.sleep($0) }, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        let relay = try await factory.generation(at: 0)
        await relay.setTransferring(true)

        await supervisor.requestUpgrade()
        await candidateAtEndpoint.wait()
        let lan = try await factory.generation(at: 1)

        await supervisor.requestReconnect()
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 1)
        await candidateGate.signal()
        await waitUntil("better carrier takes over") { await supervisor.connectionMode == .plDirect }

        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("recovery finishes") { await supervisor.reconnectStatus == nil }
        try await Task.sleep(for: .milliseconds(50))

        #expect(await lan.disconnectCount == 0)
        #expect(await factory.count() == 2)
        #expect(await supervisor.connectionMode == .plDirect)
        #expect(await supervisor.attemptState == .connected)

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test("A reconnect requested after a better carrier took over is not absorbed by the old carrier's recovery")
    func reconnectAfterPromotionIsNotAbsorbedByTheDroppedRecovery() async throws {
        let sleeper = SleepProbe()
        let candidateGate = TestSignal()
        let candidateAtEndpoint = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint(), muxClosedAfterSuccessCount: 0, muxClosedError: openFailure),
            .success(lanEndpoint, connectedEndpointSignal: candidateAtEndpoint, connectedEndpointGate: candidateGate),
            .success(lanEndpoint)
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: { try await sleeper.sleep($0) }, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        let relay = try await factory.generation(at: 0)
        await relay.setTransferring(true)

        await supervisor.requestUpgrade()
        await candidateAtEndpoint.wait()
        let lan = try await factory.generation(at: 1)
        _ = try? await supervisor.openStream()
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 1)
        await candidateGate.signal()
        await waitUntil("better carrier takes over") { await supervisor.connectionMode == .plDirect }

        // The owner asks for a reconnect while the relay's recovery still waits.
        await supervisor.requestReconnect()
        await sleeper.releaseFirstSleep(duration: retrySleep)
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 2)
        #expect(await lan.disconnectCount == 0)
        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("current carrier replaced") { await lan.disconnectCount == 1 }
        await waitUntil("replacement connected") { await factory.count() == 3 }
        await waitUntil("replacement is current") { await supervisor.attemptState == .connected }

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test("A better carrier that fails while the old recovery waits is still recovered, once")
    func failedPromotedCarrierIsStillRecovered() async throws {
        let sleeper = SleepProbe()
        let candidateGate = TestSignal()
        let candidateAtEndpoint = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint(), muxClosedAfterSuccessCount: 0, muxClosedError: openFailure),
            .success(lanEndpoint, connectedEndpointSignal: candidateAtEndpoint, connectedEndpointGate: candidateGate),
            .success(relayEndpoint()),
            .success(relayEndpoint())
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: { try await sleeper.sleep($0) }, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        let relay = try await factory.generation(at: 0)
        await relay.setTransferring(true)

        await supervisor.requestUpgrade()
        await candidateAtEndpoint.wait()
        let lan = try await factory.generation(at: 1)
        _ = try? await supervisor.openStream()
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 1)
        await candidateGate.signal()
        await waitUntil("better carrier takes over") { await supervisor.connectionMode == .plDirect }

        // The carrier that took over fails before the old recovery wakes.
        await lan.fail(.transportFailed("lan lost"))
        await waitUntil("failure seen") { await supervisor.attemptState != .connected }

        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("replacement connects") { await factory.count() == 3 }
        await waitUntil("replacement is current") { await supervisor.attemptState == .connected }
        let replacement = try await factory.generation(at: 2)

        // The failed carrier's own recovery wakes to a healthy replacement and
        // has nothing left to do.
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 2)
        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("second recovery finishes") { await supervisor.reconnectStatus == nil }
        try await Task.sleep(for: .milliseconds(50))

        #expect(await lan.disconnectCount == 1)
        #expect(await replacement.disconnectCount == 0)
        #expect(await factory.count() == 3)
        #expect(await supervisor.attemptState == .connected)

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test("A reconnect requested after a better carrier took over replaces that carrier")
    func reconnectAfterPromotionReplacesTheCurrentCarrier() async throws {
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint()), .success(lanEndpoint), .success(relayEndpoint())
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: { try await sleeper.sleep($0) }, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        let relay = try await factory.generation(at: 0)
        await relay.setTransferring(true)
        await supervisor.requestUpgrade()
        await waitUntil("better carrier takes over") { await supervisor.connectionMode == .plDirect }
        let lan = try await factory.generation(at: 1)

        // The request names no carrier, so it means the current one.
        await supervisor.requestReconnect()
        await sleeper.waitForSleepCount(excluding: stabilitySleep, target: 1)
        await sleeper.releaseFirstSleep(duration: retrySleep)
        await waitUntil("current carrier replaced") { await lan.disconnectCount == 1 }
        await waitUntil("replacement connected") { await factory.count() == 3 }

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test("Disconnecting while a better carrier is still connecting closes it without promoting it")
    func disconnectRetiresHeldCandidate() async throws {
        let candidateGate = TestSignal()
        let candidateAtEndpoint = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint()),
            .success(lanEndpoint, connectedEndpointSignal: candidateAtEndpoint, connectedEndpointGate: candidateGate)
        ])
        let supervisor = fakeSupervisor(factory: factory, policy: returningPolicy)
        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        await supervisor.requestUpgrade()
        await candidateAtEndpoint.wait()

        await supervisor.disconnect()
        await candidateGate.signal()
        let candidate = try await factory.generation(at: 1)
        await waitUntil("held candidate closed") { await candidate.disconnectCount == 1 }
        #expect(await supervisor.connectionMode == nil)
        #expect(await supervisor.attemptState == .idle)
    }
}
