// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let lanEndpoint = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "test")
private let returningPolicy = SessionPolicy(returnsToBetterPath: true)

/// The first long upgrade delay waits on `gate`; later long delays really wait
/// (until the test ends). Every shorter sleep, the drain poll, is quick.
private actor LongSleepCounter {
    private var count = 0
    func next() -> Int {
        count += 1
        return count
    }
}

private func gatedUpgradeSleeper(_ gate: TestSignal) -> @Sendable (Duration) async throws -> Void {
    let counter = LongSleepCounter()
    return { duration in
        if duration >= .seconds(30) {
            if await counter.next() == 1 {
                await gate.wait()
                try Task.checkCancellation()
            } else {
                try await Task.sleep(for: .seconds(3600))
            }
        } else {
            try await Task.sleep(for: .milliseconds(5))
        }
    }
}

private func waitFor(
    timeout: Duration = .seconds(5),
    _ condition: @Sendable () async -> Bool
) async throws {
    let deadline = ContinuousClock.now + timeout
    while !(await condition()) {
        guard ContinuousClock.now < deadline else {
            Issue.record("condition not met within \(timeout)")
            throw CancellationError()
        }
        try await Task.sleep(for: .milliseconds(5))
    }
}

@Suite("Supervisor returns to a better path", .serialized)
struct TunnelSupervisorUpgradeTests {
    @Test("On relay with a LAN path planned, the LAN carrier takes over and the relay drains after its transfer")
    func upgradesToTheBetterPathAndDrainsTheOldCarrier() async throws {
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [.success(relay), .success(lanEndpoint)])
        let upgradeGate = TestSignal()
        let supervisor = fakeSupervisor(factory: factory, upgradeSleeper: gatedUpgradeSleeper(upgradeGate), policy: returningPolicy)

        let first = try await supervisor.connect(endpoints: [lanEndpoint, relay])
        #expect(first == relay.connectedVia)
        let relayGeneration = try await factory.generation(at: 0)
        await relayGeneration.setTransferring(true)

        await upgradeGate.signal()
        try await waitFor { await factory.count() == 2 }
        let lanGeneration = try await factory.generation(at: 1)
        try await waitFor { await supervisor.connectionMode == .plDirect }

        // Only the better path is dialed, and the relay carrier is still up while it carries a transfer.
        let upgradeDial = await lanGeneration.connectCalls().first?.endpoints
        #expect(upgradeDial == [lanEndpoint])
        try await Task.sleep(for: .milliseconds(50))
        #expect(await relayGeneration.disconnectCount == 0)
        _ = try await supervisor.openStream()

        await relayGeneration.setTransferring(false)
        try await waitFor { await relayGeneration.disconnectCount == 1 }
        #expect(await lanGeneration.disconnectCount == 0)
        await supervisor.disconnect()
    }

    @Test("A failed upgrade leaves the working carrier alone")
    func failedUpgradeKeepsTheCurrentCarrier() async throws {
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [.success(relay), .failure(.unreachable)])
        let upgradeGate = TestSignal()
        let supervisor = fakeSupervisor(factory: factory, upgradeSleeper: gatedUpgradeSleeper(upgradeGate), policy: returningPolicy)

        _ = try await supervisor.connect(endpoints: [lanEndpoint, relay])
        await upgradeGate.signal()
        try await waitFor { await factory.count() == 2 }
        let failedUpgrade = try await factory.generation(at: 1)
        try await waitFor { await failedUpgrade.disconnectCount == 1 }

        let relayGeneration = try await factory.generation(at: 0)
        #expect(await relayGeneration.disconnectCount == 0)
        #expect(await supervisor.connectionMode == .plViaSpl)
        #expect(await supervisor.attemptState == .connected)
        _ = try await supervisor.openStream()
        await supervisor.disconnect()
    }

    @Test("A carrier already on the best planned path never tries to upgrade")
    func bestPathDoesNotUpgrade() async throws {
        let factory = FakeGenerationFactory(scripts: [.success(lanEndpoint)])
        let supervisor = fakeSupervisor(factory: factory, upgradeSleeper: { _ in }, policy: returningPolicy)

        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        await supervisor.requestUpgrade()
        try await Task.sleep(for: .milliseconds(50))
        #expect(await factory.count() == 1)
        await supervisor.disconnect()
    }

    @Test("Without the policy, a supervisor on a worse path stays where it is")
    func upgradeIsOptIn() async throws {
        let factory = FakeGenerationFactory(scripts: [.success(relayEndpoint())])
        let supervisor = fakeSupervisor(factory: factory, upgradeSleeper: { _ in })

        _ = try await supervisor.connect(endpoints: [lanEndpoint, relayEndpoint()])
        await supervisor.requestUpgrade()
        try await Task.sleep(for: .milliseconds(50))
        #expect(await factory.count() == 1)
        await supervisor.disconnect()
    }

    @Test("Disconnecting the supervisor also closes a carrier that is still draining")
    func disconnectClosesDrainingCarrier() async throws {
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [.success(relay), .success(lanEndpoint)])
        let upgradeGate = TestSignal()
        let supervisor = fakeSupervisor(factory: factory, upgradeSleeper: gatedUpgradeSleeper(upgradeGate), policy: returningPolicy)

        _ = try await supervisor.connect(endpoints: [lanEndpoint, relay])
        let relayGeneration = try await factory.generation(at: 0)
        await relayGeneration.setTransferring(true)
        await upgradeGate.signal()
        try await waitFor { await supervisor.connectionMode == .plDirect }
        #expect(await relayGeneration.disconnectCount == 0)

        await supervisor.disconnect()
        #expect(await relayGeneration.disconnectCount == 1)
    }
}
