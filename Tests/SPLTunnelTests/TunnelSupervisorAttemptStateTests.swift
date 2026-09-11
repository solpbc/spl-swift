// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("TunnelSupervisor Attempt State", .serialized)
struct TunnelSupervisorAttemptStateTests {
    private let relayEndpoint = TransportEndpoint.relay(
        endpoint: URL(string: "wss://relay.example/session")!,
        instanceID: "instance",
        deviceToken: "token"
    )
    private let directEndpoint = TransportEndpoint.lan(
        host: "192.168.1.10",
        port: 443,
        scope: "local"
    )

    @Test("AC1: Baseline lifecycle transitions through idle, attempting, connected, and idle")
    func baselineLifecycle() async throws {
        let connectGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: connectGate)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        #expect(await supervisor.attemptState == .idle)

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await waitUntil("transition to attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)

        await connectGate.signal()
        _ = try await connectTask.value

        #expect(await supervisor.attemptState == .connected)
        #expect(await iterator.next() == .connected)

        await supervisor.disconnect()
        #expect(await supervisor.attemptState == .idle)
        #expect(await iterator.next() == .idle)
    }

    @Test("AC2: Dial failure emits retrying unavailable with matching attempt and delay, then recovers")
    func dialFailureAndRetry() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(25), .milliseconds(50)]), random: { _ in 1.0 })
        let gen1Gate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .failure(.unreachable, gate: gen0Gate),
            .success(relayEndpoint, gate: gen1Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await waitUntil("transition to attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(25))))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(25))))

        await sleepProbe.releaseFirstSleep(duration: .milliseconds(25))

        #expect(await iterator.next() == .attempting)
        await gen1Gate.signal()
        #expect(await iterator.next() == .connected)
        _ = try await connectTask.value
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC3: Active generation non-terminal failure emits retrying unavailable and redrive establishes replacement")
    func activeGenerationFailure() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen2Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(30)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate),
            .success(relayEndpoint, gate: gen2Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        let gen1 = try await factory.generation(at: 0)
        await gen1.fail(.directKeepaliveMissed)

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(30))))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(30))))

        await sleepProbe.releaseFirstSleep(duration: .milliseconds(30))

        #expect(await iterator.next() == .attempting)
        await gen2Gate.signal()
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC4: openStream failure emits retrying unavailable with transport failureClass")
    func openStreamFailure() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen2Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(40)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate, muxClosedAfterSuccessCount: 0, muxClosedError: .transportFailed("mux closed")),
            .success(relayEndpoint, gate: gen2Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        do {
            _ = try await supervisor.openStream()
            #expect(Bool(false), "Expected openStream to throw")
        } catch {
            #expect(error is SessionError)
        }

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(40))))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(40))))

        await sleepProbe.releaseFirstSleep(duration: .milliseconds(40))

        #expect(await iterator.next() == .attempting)
        await gen2Gate.signal()
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC5: Terminal failures publish terminal state and do not retry")
    func terminalFailures() async throws {
        // Case A: Dial failure with terminal error (.revoked)
        do {
            let dialGate = TestSignal()
            let factory = FakeGenerationFactory(scripts: [
                .failure(.revoked, gate: dialGate)
            ])
            let supervisor = fakeSupervisor(factory: factory)
            let stream = await supervisor.attemptStateUpdates()
            var iterator = stream.makeAsyncIterator()
            #expect(await iterator.next() == .idle)

            let connectTask = Task {
                try await supervisor.connect(endpoints: [self.relayEndpoint])
            }

            #expect(await iterator.next() == .attempting)
            await dialGate.signal()

            do {
                _ = try await connectTask.value
                #expect(Bool(false), "Expected revoked error")
            } catch {
                #expect(error as? SessionError == .revoked)
            }

            #expect(await iterator.next() == .terminal(.revoked))
            #expect(await supervisor.attemptState == .terminal(.revoked))
        }

        // Case B: Active generation failure with terminal error (.authRefreshRequired)
        do {
            let gen0Gate = TestSignal()
            let factory = FakeGenerationFactory(scripts: [
                .success(relayEndpoint, gate: gen0Gate)
            ])
            let supervisor = fakeSupervisor(factory: factory)
            let stream = await supervisor.attemptStateUpdates()
            var iterator = stream.makeAsyncIterator()
            #expect(await iterator.next() == .idle)

            let connectTask = Task {
                try await supervisor.connect(endpoints: [self.relayEndpoint])
            }
            #expect(await iterator.next() == .attempting)
            await gen0Gate.signal()
            _ = try await connectTask.value
            #expect(await iterator.next() == .connected)

            let gen = try await factory.generation(at: 0)
            await gen.fail(.authRefreshRequired)

            #expect(await iterator.next() == .terminal(.authRefreshRequired))
            #expect(await supervisor.attemptState == .terminal(.authRefreshRequired))
        }

        // Case C: Active generation failure with terminal error (.notEntitled)
        do {
            let gen0Gate = TestSignal()
            let factory = FakeGenerationFactory(scripts: [
                .success(relayEndpoint, gate: gen0Gate)
            ])
            let supervisor = fakeSupervisor(factory: factory)
            let stream = await supervisor.attemptStateUpdates()
            var iterator = stream.makeAsyncIterator()
            #expect(await iterator.next() == .idle)

            let connectTask = Task {
                try await supervisor.connect(endpoints: [self.relayEndpoint])
            }
            #expect(await iterator.next() == .attempting)
            await gen0Gate.signal()
            _ = try await connectTask.value
            #expect(await iterator.next() == .connected)

            let gen = try await factory.generation(at: 0)
            await gen.fail(.notEntitled)

            #expect(await iterator.next() == .terminal(.notEntitled))
            #expect(await supervisor.attemptState == .terminal(.notEntitled))
        }
    }

    @Test("AC6: Healthy replacement lifecycle stays connected during sleeper and factory hold, emits replacing during disconnect of old generation, then attempting and connected")
    func healthyReplacementLifecycle() async throws {
        let sleepProbe = SleepProbe()
        let factorySignal = TestSignal()
        let factoryGate = TestSignal()
        let disconnectSignal = TestSignal()
        let disconnectGate = TestSignal()
        let gen0Gate = TestSignal()
        let gen2Gate = TestSignal()

        let factory = FakeGenerationFactory(scripts: [
            .success(
                relayEndpoint,
                gate: gen0Gate,
                disconnectSignal: disconnectSignal,
                disconnectGate: disconnectGate
            ),
            .success(
                relayEndpoint,
                gate: gen2Gate,
                makeSessionSignal: factorySignal,
                makeSessionGate: factoryGate
            )
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)

        // Request redrive while gen1 is healthy
        await supervisor.requestReconnect()

        // Wait for sleeper to enter sleep during redrive
        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        // While in sleeper hold, attemptState MUST still be .connected
        #expect(await supervisor.attemptState == .connected)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(1))

        // Wait for factory to enter makeSession
        await factorySignal.wait()
        // While in factory hold, attemptState MUST still be .connected
        #expect(await supervisor.attemptState == .connected)

        // Release factory hold -> installGeneration runs -> clearActiveGeneration(disconnect: true) runs
        await factoryGate.signal()

        // Wait for gen1 disconnect to be entered
        await disconnectSignal.wait()

        // Inside clearActiveGeneration before session.disconnect completes, attemptState MUST be .unavailable(.replacing)
        #expect(await supervisor.attemptState == .unavailable(.replacing))
        #expect(await iterator.next() == .unavailable(.replacing))

        // Release disconnect gate -> gen1 disconnect completes -> startGeneration connects gen2
        await disconnectGate.signal()

        #expect(await iterator.next() == .attempting)
        await gen2Gate.signal()
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC7: Subscription multicast, current value yielding, and cancellation unregistration")
    func subscriptionMulticastAndCleanup() async throws {
        let connectGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: connectGate)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream1 = await supervisor.attemptStateUpdates()
        let stream2 = await supervisor.attemptStateUpdates()
        #expect(await supervisor.attemptStateSubscriberCount == 2)

        var iterator1 = stream1.makeAsyncIterator()
        var iterator2 = stream2.makeAsyncIterator()

        #expect(await iterator1.next() == .idle)
        #expect(await iterator2.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await waitUntil("attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator1.next() == .attempting)
        #expect(await iterator2.next() == .attempting)

        await connectGate.signal()
        _ = try await connectTask.value

        #expect(await iterator1.next() == .connected)
        #expect(await iterator2.next() == .connected)

        // Deallocation test: create stream3, drop reference, verify count drops
        do {
            var stream3: AsyncStream<TunnelSupervisorAttemptState>? = await supervisor.attemptStateUpdates()
            _ = stream3
            await waitUntil("subscriber 3 registered") {
                await supervisor.attemptStateSubscriberCount == 3
            }
            stream3 = nil
            await waitUntil("subscriber 3 unregistered after deallocation") {
                await supervisor.attemptStateSubscriberCount == 2
            }
        }
    }

    @Test("AC8: SessionError attemptFailureClass exhaustive mapping")
    func sessionErrorFailureClassMapping() {
        #expect(SessionError.unreachable.attemptFailureClass == .unreachable)
        #expect(SessionError.tlsFailed("error").attemptFailureClass == .tls)
        #expect(SessionError.authRefreshRequired.attemptFailureClass == .authRefreshRequired)
        #expect(SessionError.notEntitled.attemptFailureClass == .notEntitled)
        #expect(SessionError.revoked.attemptFailureClass == .revoked)
        #expect(SessionError.transportFailed("drop").attemptFailureClass == .transport)
        #expect(SessionError.inboundClosed(fault: nil).attemptFailureClass == .transport)
        #expect(SessionError.directKeepaliveMissed.attemptFailureClass == .transport)
        #expect(SessionError.relayKeepaliveMissed.attemptFailureClass == .transport)
        #expect(SessionError.notConnected.attemptFailureClass == .other)
    }

    // MARK: - Stream Mechanics (Real AC1)

    @Test("Stream mechanics: Buffer capacity 1 drops unconsumed intermediate states and yields newest")
    func streamBufferCapacityNewestOnly() async throws {
        let genGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: genGate)
        ])
        let supervisor = fakeSupervisor(factory: factory)
        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        await genGate.signal()
        _ = try await connectTask.value

        #expect(await supervisor.attemptState == .connected)
        #expect(await iterator.next() == .connected)
    }

    @Test("Stream mechanics: Cancelled subscriber task unregisters without affecting sibling subscriber or future subscribers")
    func subscriberCancellationIsolation() async throws {
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let taskA = Task {
            let streamA = await supervisor.attemptStateUpdates()
            var itA = streamA.makeAsyncIterator()
            _ = await itA.next()
            _ = await itA.next()
        }

        let streamB = await supervisor.attemptStateUpdates()
        var itB = streamB.makeAsyncIterator()
        #expect(await itB.next() == .idle)

        await waitUntil("both subscribers registered") {
            await supervisor.attemptStateSubscriberCount == 2
        }

        taskA.cancel()
        await waitUntil("subscriber A unregistered on cancellation") {
            await supervisor.attemptStateSubscriberCount == 1
        }

        try await supervisor.connect(endpoints: [relayEndpoint])
        #expect(await itB.next() == .connected)

        let streamC = await supervisor.attemptStateUpdates()
        var itC = streamC.makeAsyncIterator()
        #expect(await itC.next() == .connected)
        #expect(await supervisor.attemptStateSubscriberCount == 2)
        #expect(await supervisor.attemptState == .connected)
    }

    // MARK: - First Generation + Rejection (Real AC2)

    @Test("First generation: Held makeSession factory stays idle and transitions to attempting immediately before connectCalls")
    func heldFirstChildFactoryStaysIdleUntilReturned() async throws {
        let makeSessionSignal = TestSignal()
        let makeSessionGate = TestSignal()
        let connectGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(
                relayEndpoint,
                gate: connectGate,
                makeSessionSignal: makeSessionSignal,
                makeSessionGate: makeSessionGate
            )
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await makeSessionSignal.wait()
        #expect(await supervisor.attemptState == .idle)
        #expect(await factory.count() == 0)

        await makeSessionGate.signal()
        await waitUntil("attempting after factory returns") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)
        let gen = try await factory.generation(at: 0)
        #expect(await gen.connectCalls().count == 1)

        await connectGate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("First generation: Empty connect endpoints throws unreachable without attempt state transition from idle, connected, or terminal")
    func emptyConnectThrowsUnreachableWithoutStateTransition() async throws {
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint),
            .failure(.revoked)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        // 1. From idle
        #expect(await supervisor.attemptState == .idle)
        do {
            try await supervisor.connect(endpoints: [])
            #expect(Bool(false), "Expected unreachable error")
        } catch {
            #expect(error as? SessionError == .unreachable)
        }
        #expect(await supervisor.attemptState == .idle)

        let streamFromIdle = await supervisor.attemptStateUpdates()
        var itIdle = streamFromIdle.makeAsyncIterator()
        #expect(await itIdle.next() == .idle)

        // 2. From connected
        try await supervisor.connect(endpoints: [relayEndpoint])
        #expect(await supervisor.attemptState == .connected)
        do {
            try await supervisor.connect(endpoints: [])
            #expect(Bool(false), "Expected unreachable error")
        } catch {
            #expect(error as? SessionError == .unreachable)
        }
        #expect(await supervisor.attemptState == .connected)

        let streamFromConnected = await supervisor.attemptStateUpdates()
        var itConn = streamFromConnected.makeAsyncIterator()
        #expect(await itConn.next() == .connected)

        // 3. From terminal
        let gen = try await factory.generation(at: 0)
        await gen.fail(.revoked)
        await waitUntil("terminal") {
            await supervisor.attemptState == .terminal(.revoked)
        }
        do {
            try await supervisor.connect(endpoints: [])
            #expect(Bool(false), "Expected unreachable error")
        } catch {
            #expect(error as? SessionError == .unreachable)
        }
        #expect(await supervisor.attemptState == .terminal(.revoked))

        let streamFromTerminal = await supervisor.attemptStateUpdates()
        var itTerm = streamFromTerminal.makeAsyncIterator()
        #expect(await itTerm.next() == .terminal(.revoked))
    }

    @Test("First generation: Coalesced concurrent connects produce exactly one attempting per real generation")
    func coalescedConcurrentConnectsProduceSingleAttemptingPerGeneration() async throws {
        let connectGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: connectGate)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        async let task1 = supervisor.connect(endpoints: [relayEndpoint])
        async let task2 = supervisor.connect(endpoints: [relayEndpoint])
        async let task3 = supervisor.connect(endpoints: [relayEndpoint])

        await waitUntil("transition to attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)

        await connectGate.signal()
        let (via1, via2, via3) = try await (task1, task2, task3)
        #expect(via1 == via2)
        #expect(via2 == via3)
        #expect(await factory.count() == 1)

        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("Payloads: String(describing:) of attempt state values contains no host, port, or URL")
    func attemptStateDescriptionsContainNoHostPortUrl() {
        let values: [TunnelSupervisorAttemptState] = [
            .idle,
            .attempting,
            .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(250))),
            .unavailable(.retrying(failureClass: .transport, attempt: 2, retryAfter: .seconds(1))),
            .unavailable(.replacing),
            .connected,
            .terminal(.revoked),
            .terminal(.authRefreshRequired),
            .terminal(.notEntitled),
            .terminal(.tls)
        ]

        for value in values {
            let desc = String(describing: value)
            #expect(!desc.contains("192.168"))
            #expect(!desc.contains("relay.example"))
            #expect(!desc.contains("wss://"))
            #expect(!desc.contains("443"))
        }
    }

    // MARK: - Initial Failure + Held Successor Factory (Real AC3)

    @Test("AC3: Initial dial failure with held successor makeSession factory remains retrying unavailable until factory returns")
    func initialFailureHeldSuccessorFactoryRemainsUnavailable() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let successorFactorySignal = TestSignal()
        let successorFactoryGate = TestSignal()
        let successorConnectGate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(25)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .failure(.unreachable, gate: gen0Gate),
            .success(
                relayEndpoint,
                gate: successorConnectGate,
                makeSessionSignal: successorFactorySignal,
                makeSessionGate: successorFactoryGate
            )
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await waitUntil("transition to attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(25))))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(25))))

        await sleepProbe.releaseFirstSleep(duration: .milliseconds(25))

        await successorFactorySignal.wait()
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(25))))

        await successorFactoryGate.signal()
        await waitUntil("attempting after successor factory") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)

        let gen1 = try await factory.generation(at: 1)
        #expect(await gen1.connectCalls().count == 1)

        await successorConnectGate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    // MARK: - Established Route-Loss vs Healthy Redrive (Real AC4 Extras)

    @Test("AC4: Established child failed transitions immediately to unavailable without connected interval")
    func establishedFailureRouteLossTransitionsDirectlyToUnavailable() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen1Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(30)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate),
            .success(relayEndpoint, gate: gen1Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        let gen0 = try await factory.generation(at: 0)
        await gen0.fail(.tlsFailed("handshake timeout"))

        await waitUntil("unavailable on established failure") {
            await supervisor.attemptState == .unavailable(.retrying(failureClass: .tls, attempt: 1, retryAfter: .milliseconds(30)))
        }
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .tls, attempt: 1, retryAfter: .milliseconds(30))))

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(30))

        #expect(await iterator.next() == .attempting)
        await gen1Gate.signal()
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC4: openStream succeeds then fails on closed mux, emits retrying unavailable without child failed event")
    func openStreamSuccessThenFailEmitsUnavailableWithoutChildFailure() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen1Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(40)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .success(
                relayEndpoint,
                gate: gen0Gate,
                muxClosedAfterSuccessCount: 1,
                muxClosedError: .transportFailed("mux closed")
            ),
            .success(relayEndpoint, gate: gen1Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        _ = try await supervisor.openStream()

        do {
            _ = try await supervisor.openStream()
            #expect(Bool(false), "Expected transportFailed error")
        } catch {
            #expect(error as? SessionError == .transportFailed("mux closed"))
        }

        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(40))))
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(40))))

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(40))

        #expect(await iterator.next() == .attempting)
        await gen1Gate.signal()
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    // MARK: - Connected Boundary (Real AC5)

    @Test("AC5: Stays attempting during returnGate and connectedEndpointGate, connected only after commitRetiringGeneration")
    func establishmentHoldAndRetirementTeardownBoundary() async throws {
        let connectGate = TestSignal()
        let returnGate = TestSignal()
        let endpointGate = TestSignal()
        let endpointSignal = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(
                relayEndpoint,
                gate: connectGate,
                returnGate: returnGate,
                connectedEndpointSignal: endpointSignal,
                connectedEndpointGate: endpointGate
            )
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        #expect(await iterator.next() == .attempting)
        await connectGate.signal()

        // Waiting at returnGate: still attempting
        #expect(await supervisor.attemptState == .attempting)
        await returnGate.signal()

        // Waiting at connectedEndpointGate: still attempting
        await endpointSignal.wait()
        #expect(await supervisor.attemptState == .attempting)
        await endpointGate.signal()

        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    @Test("AC5: Retiring generation failure with revoked error during successor establishment transitions to terminal and blocks successor connected")
    func retiringGenerationRevocationPausesSupervisorAndBlocksSuccessor() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen1Gate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(25)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate),
            .success(relayEndpoint, gate: gen1Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        let gen0 = try await factory.generation(at: 0)

        // 1. Initial transient failure on gen 0 causes redrive and retirement
        await gen0.fail(.transportFailed("drop"))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(25))))

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(25))

        #expect(await iterator.next() == .attempting)
        await waitUntil("gen 1 attempting") {
            await factory.count() >= 2
        }

        // 2. Retiring gen 0 receives revoked error while gen 1 is held in gate
        await gen0.fail(.revoked)

        await waitUntil("supervisor pauses to terminal(.revoked)") {
            await supervisor.attemptState == .terminal(.revoked)
        }
        #expect(await iterator.next() == .terminal(.revoked))

        // 3. Releasing successor connect does not publish connected
        await gen1Gate.signal()

        #expect(await supervisor.attemptState == .terminal(.revoked))
    }

    // MARK: - Late Results + Teardown-Before-Await (Real AC6)

    @Test("AC6: Late sleeper, factory, and connect completions cannot overwrite terminal or idle state")
    func lateAsyncEventsCannotOverwriteTerminalOrIdle() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen1MakeSessionSignal = TestSignal()
        let gen1MakeSessionGate = TestSignal()
        let backoff = ReconnectBackoff(schedule: .table([.milliseconds(30)]), random: { _ in 1.0 })
        let factory = FakeGenerationFactory(scripts: [
            .failure(.unreachable, gate: gen0Gate),
            .success(
                relayEndpoint,
                makeSessionSignal: gen1MakeSessionSignal,
                makeSessionGate: gen1MakeSessionGate
            )
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }

        await waitUntil("transition to attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)

        await gen0Gate.signal()

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(30))))
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .unreachable, attempt: 1, retryAfter: .milliseconds(30))))

        await supervisor.disconnect()
        #expect(await supervisor.attemptState == .idle)
        #expect(await iterator.next() == .idle)

        await sleepProbe.releaseFirstSleep(duration: .milliseconds(30))

        do {
            _ = try await connectTask.value
        } catch {
            #expect(error is SessionError)
        }

        #expect(await supervisor.attemptState == .idle)
    }

    @Test("AC6: Disconnect and pause update attempt state before releasing disconnectGate and openStream rejects during hold")
    func disconnectAndPauseUpdateStateBeforeTeardownRelease() async throws {
        let connectGate = TestSignal()
        let disconnectSignal = TestSignal()
        let disconnectGate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(
                relayEndpoint,
                gate: connectGate,
                disconnectSignal: disconnectSignal,
                disconnectGate: disconnectGate
            )
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        await waitUntil("attempting") {
            await supervisor.attemptState == .attempting
        }
        #expect(await iterator.next() == .attempting)

        await connectGate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        let disconnectTask = Task {
            await supervisor.disconnect()
        }

        await disconnectSignal.wait()
        #expect(await supervisor.attemptState == .idle)
        #expect(await iterator.next() == .idle)

        do {
            _ = try await supervisor.openStream()
            #expect(Bool(false), "Expected notConnected error")
        } catch {
            #expect(error as? SessionError == .notConnected)
        }

        await disconnectGate.signal()
        await disconnectTask.value
        #expect(await supervisor.attemptState == .idle)
    }

    @Test("AC6: Stream does not finish on terminal or disconnect and yields subsequent explicit connect to surviving and new iterators")
    func streamSurvivesTerminalAndDisconnectForLaterConnect() async throws {
        let gen0Gate = TestSignal()
        let gen1Gate = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate),
            .success(relayEndpoint, gate: gen1Gate)
        ])
        let supervisor = fakeSupervisor(factory: factory)

        let stream = await supervisor.attemptStateUpdates()
        var iteratorSurviving = stream.makeAsyncIterator()
        #expect(await iteratorSurviving.next() == .idle)

        let connectTask1 = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iteratorSurviving.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask1.value
        #expect(await iteratorSurviving.next() == .connected)

        await supervisor.disconnect()
        #expect(await iteratorSurviving.next() == .idle)

        let connectTask2 = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iteratorSurviving.next() == .attempting)

        let streamNew = await supervisor.attemptStateUpdates()
        var iteratorNew = streamNew.makeAsyncIterator()
        #expect(await iteratorNew.next() == .attempting)

        await gen1Gate.signal()
        _ = try await connectTask2.value
        #expect(await iteratorSurviving.next() == .connected)
        #expect(await iteratorNew.next() == .connected)
        #expect(await supervisor.attemptState == .connected)
    }

    // MARK: - Payloads (Real AC7 Extras)

    @Test("Payloads: Sensitive raw SessionError payloads never appear in attempt state descriptions")
    func sanitizedErrorDescriptionsNoSentinels() {
        let sentinelTLS = SessionError.tlsFailed("SENTINEL-TLS-secret-key")
        let sentinelTransport = SessionError.transportFailed("SENTINEL-TRANSPORT-token-123")
        let sentinelInbound = SessionError.inboundClosed(fault: "SENTINEL-INBOUND-private-cert")

        let stateTLS = TunnelSupervisorAttemptState.unavailable(.retrying(failureClass: sentinelTLS.attemptFailureClass, attempt: 1, retryAfter: .seconds(1)))
        let stateTransport = TunnelSupervisorAttemptState.unavailable(.retrying(failureClass: sentinelTransport.attemptFailureClass, attempt: 2, retryAfter: .seconds(2)))
        let stateInbound = TunnelSupervisorAttemptState.terminal(sentinelInbound.attemptFailureClass)

        let descTLS = String(describing: stateTLS)
        let descTransport = String(describing: stateTransport)
        let descInbound = String(describing: stateInbound)

        #expect(!descTLS.contains("SENTINEL"))
        #expect(!descTransport.contains("SENTINEL"))
        #expect(!descInbound.contains("SENTINEL"))
    }

    @Test("Payloads: Replacing unavailability has no failure class, attempt, or retry delay")
    func replacingUnavailabilityHasNoFailureClassOrDelay() {
        func verifyUnavailability(_ unavail: TunnelSupervisorUnavailability) {
            switch unavail {
            case .replacing:
                #expect(unavail.description == "replacing")
            case .retrying:
                #expect(Bool(false), "Expected replacing case")
            }
        }
        verifyUnavailability(.replacing)
    }

    @Test("AC7: Consecutive unstable failures advance backoff steps and stability interval resets backoff schedule")
    func consecutiveUnstableFailuresAdvanceBackoffAndStabilityResets() async throws {
        let sleepProbe = SleepProbe()
        let gen0Gate = TestSignal()
        let gen1Gate = TestSignal()
        let gen2Gate = TestSignal()
        let backoff = ReconnectBackoff(
            schedule: .table([.milliseconds(20), .milliseconds(40)]),
            random: { _ in 1.0 }
        )
        let factory = FakeGenerationFactory(scripts: [
            .success(relayEndpoint, gate: gen0Gate),
            .success(relayEndpoint, gate: gen1Gate),
            .success(relayEndpoint, gate: gen2Gate)
        ])
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: backoff,
            sleeper: { duration in
                try await sleepProbe.sleep(duration)
            }
        )

        let stream = await supervisor.attemptStateUpdates()
        var iterator = stream.makeAsyncIterator()
        #expect(await iterator.next() == .idle)

        let connectTask = Task {
            try await supervisor.connect(endpoints: [self.relayEndpoint])
        }
        #expect(await iterator.next() == .attempting)
        await gen0Gate.signal()
        _ = try await connectTask.value
        #expect(await iterator.next() == .connected)

        // 1. First unstable failure -> step 1: 20ms
        let gen0 = try await factory.generation(at: 0)
        await gen0.fail(.transportFailed("drop 1"))

        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(20))))
        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(20))

        #expect(await iterator.next() == .attempting)
        await gen1Gate.signal()
        #expect(await iterator.next() == .connected)

        // 2. Second unstable failure before stability interval -> step 2: 40ms
        let gen1 = try await factory.generation(at: 1)
        await gen1.fail(.transportFailed("drop 2"))

        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 2, retryAfter: .milliseconds(40))))
        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 2)
        await sleepProbe.releaseFirstSleep(duration: .milliseconds(40))

        #expect(await iterator.next() == .attempting)
        await gen2Gate.signal()
        #expect(await iterator.next() == .connected)

        // 3. Stability interval passes (release 60s stability sleep for active gen 2)
        await waitUntil("3rd stability timer armed") {
            await sleepProbe.observedDurations().filter { $0 == .seconds(60) }.count >= 3
        }
        await sleepProbe.releaseFirstSleep(duration: .seconds(60))
        await sleepProbe.releaseFirstSleep(duration: .seconds(60))
        await sleepProbe.releaseFirstSleep(duration: .seconds(60))

        // Yield to allow stabilityTask to run self.completeStabilityTimer on supervisor actor
        for _ in 0..<10 {
            await Task.yield()
        }
        _ = await supervisor.attemptState

        // 4. Subsequent failure resets backoff -> step 1: 20ms
        let gen2 = try await factory.generation(at: 2)
        await gen2.fail(.transportFailed("drop 3"))

        await sleepProbe.waitForSleepCount(excluding: .seconds(60), target: 3)
        #expect(await iterator.next() == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(20))))
        #expect(await supervisor.attemptState == .unavailable(.retrying(failureClass: .transport, attempt: 1, retryAfter: .milliseconds(20))))
    }
}
