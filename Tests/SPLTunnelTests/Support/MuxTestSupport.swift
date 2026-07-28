// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

enum MuxTestError: Error, Equatable, Sendable {
    case sinkFailure
    case timedOut(String)
}

actor MuxFrameRecorder {
    private var decoder = FrameDecoder()
    private var recordedFrames: [Frame] = []

    func record(_ bytes: Data) throws {
        decoder.feed(bytes)
        while let frame = try decoder.next() {
            recordedFrames.append(frame)
        }
    }

    func frames() -> [Frame] {
        recordedFrames
    }

    func reset() {
        decoder = FrameDecoder()
        recordedFrames.removeAll()
    }

    func count() -> Int {
        recordedFrames.count
    }
}

actor SelectiveMuxSink {
    enum FailureMode: Sendable {
        case any
        case flags(UInt8)
        case first
    }

    private let failureMode: FailureMode
    private var decoder = FrameDecoder()
    private var recordedFrames: [Frame] = []
    private var didFail = false

    init(failureMode: FailureMode) {
        self.failureMode = failureMode
    }

    func recordOrThrow(_ bytes: Data) throws {
        if case .first = failureMode, !didFail {
            didFail = true
            throw MuxTestError.sinkFailure
        }

        decoder.feed(bytes)
        var decoded: [Frame] = []
        while let frame = try decoder.next() {
            recordedFrames.append(frame)
            decoded.append(frame)
        }

        switch failureMode {
        case .any:
            if !decoded.isEmpty {
                throw MuxTestError.sinkFailure
            }
        case let .flags(flags):
            if decoded.contains(where: { $0.flags == flags }) {
                throw MuxTestError.sinkFailure
            }
        case .first:
            break
        }
    }

    func frames() -> [Frame] {
        recordedFrames
    }

    func matchingFrameCount(flags: UInt8) -> Int {
        recordedFrames.filter { $0.flags == flags }.count
    }
}

actor BlockingFirstMuxSink {
    private var decoder = FrameDecoder()
    private var recordedFrames: [Frame] = []
    private var enteredContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?
    private var didEnter = false
    private var didBlock = false

    func record(_ bytes: Data) async throws {
        decoder.feed(bytes)
        while let frame = try decoder.next() {
            recordedFrames.append(frame)
        }

        guard !didBlock else {
            return
        }
        didBlock = true
        didEnter = true
        enteredContinuation?.resume()
        enteredContinuation = nil
        await withCheckedContinuation { continuation in
            releaseContinuation = continuation
        }
    }

    func waitUntilEntered() async {
        if didEnter {
            return
        }
        await withCheckedContinuation { continuation in
            enteredContinuation = continuation
        }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }

    func frames() -> [Frame] {
        recordedFrames
    }
}

actor KeepaliveTickGate {
    private var waitingTickContinuations: [CheckedContinuation<Void, Error>] = []
    private var observedTickContinuations: [CheckedContinuation<Void, Never>] = []
    private var observedTicks = 0

    func sleep(_: Duration) async throws {
        observedTicks += 1
        let observers = observedTickContinuations
        observedTickContinuations.removeAll()
        for observer in observers {
            observer.resume()
        }

        try await withCheckedThrowingContinuation { continuation in
            waitingTickContinuations.append(continuation)
        }
    }

    func waitForObservedTick(count: Int = 1) async {
        if observedTicks >= count {
            return
        }
        await withCheckedContinuation { continuation in
            observedTickContinuations.append(continuation)
        }
    }

    func releaseOne() {
        guard !waitingTickContinuations.isEmpty else {
            return
        }
        let continuation = waitingTickContinuations.removeFirst()
        continuation.resume()
    }

    func releaseAll() {
        let continuations = waitingTickContinuations
        waitingTickContinuations.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }

    func cancelAll() {
        let continuations = waitingTickContinuations
        waitingTickContinuations.removeAll()
        for continuation in continuations {
            continuation.resume(throwing: CancellationError())
        }
    }
}

actor AsyncResultBox<Value: Sendable> {
    private var value: Value?

    func store(_ value: Value) {
        self.value = value
    }

    func take() -> Value? {
        let current = value
        value = nil
        return current
    }

    func snapshot() -> Value? {
        value
    }
}

func rawMuxFrame(streamID: UInt32, flags: UInt8, payload: Data = Data()) -> Data {
    var data = Data()
    data.reserveCapacity(8 + payload.count)
    data.append(UInt8((streamID >> 24) & 0xff))
    data.append(UInt8((streamID >> 16) & 0xff))
    data.append(UInt8((streamID >> 8) & 0xff))
    data.append(UInt8(streamID & 0xff))
    data.append(flags)
    data.append(UInt8((payload.count >> 16) & 0xff))
    data.append(UInt8((payload.count >> 8) & 0xff))
    data.append(UInt8(payload.count & 0xff))
    data.append(payload)
    return data
}

func encodedMuxFrames(_ frames: Frame...) throws -> Data {
    try frames.reduce(into: Data()) { partial, frame in
        partial.append(try encodeFrame(frame))
    }
}

func incomingStreamObserved(
    from stream: AsyncStream<MuxStream>,
    timeout: Duration = .milliseconds(100)
) async -> Bool {
    await withTaskGroup(of: Bool.self) { group in
        group.addTask {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() != nil
        }
        group.addTask {
            try? await Task.sleep(for: timeout)
            return false
        }

        let result = await group.next() ?? false
        group.cancelAll()
        return result
    }
}

func firstIncomingStream(
    from stream: AsyncStream<MuxStream>,
    timeout: Duration = .milliseconds(500)
) async throws -> MuxStream {
    try await withThrowingTaskGroup(of: MuxStream.self) { group in
        group.addTask {
            var iterator = stream.makeAsyncIterator()
            guard let value = await iterator.next() else {
                throw MuxTestError.timedOut("incoming stream ended")
            }
            return value
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw MuxTestError.timedOut("incoming stream")
        }

        let result = try await #require(group.next())
        group.cancelAll()
        return result
    }
}

func firstKeepaliveLoss(
    from stream: AsyncStream<Void>,
    timeout: Duration = .milliseconds(500)
) async throws {
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
            var iterator = stream.makeAsyncIterator()
            guard await iterator.next() != nil else {
                throw MuxTestError.timedOut("keepalive lost stream ended")
            }
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw MuxTestError.timedOut("keepalive lost")
        }

        try await #require(group.next())
        group.cancelAll()
    }
}

func keepaliveLossObserved(
    from stream: AsyncStream<Void>,
    timeout: Duration = .milliseconds(100)
) async -> Bool {
    await withTaskGroup(of: Bool.self) { group in
        group.addTask {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() != nil
        }
        group.addTask {
            try? await Task.sleep(for: timeout)
            return false
        }

        let result = await group.next() ?? false
        group.cancelAll()
        return result
    }
}

func readInboundPayload(
    from stream: MuxStream,
    timeout: Duration = .milliseconds(500)
) async throws -> Data? {
    try await withThrowingTaskGroup(of: Data?.self) { group in
        group.addTask {
            var iterator = stream.inbound.makeAsyncIterator()
            return try await iterator.next()
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw MuxTestError.timedOut("inbound payload")
        }

        let result = try await #require(group.next())
        group.cancelAll()
        return result
    }
}

func inboundFinished(
    from stream: MuxStream,
    timeout: Duration = .milliseconds(500)
) async throws -> Bool {
    try await readInboundPayload(from: stream, timeout: timeout) == nil
}

func readPayloadThenFinish(
    from stream: MuxStream,
    timeout: Duration = .milliseconds(500)
) async throws -> (Data?, Bool) {
    try await withThrowingTaskGroup(of: (Data?, Bool).self) { group in
        group.addTask {
            var iterator = stream.inbound.makeAsyncIterator()
            let payload = try await iterator.next()
            let finished = try await iterator.next() == nil
            return (payload, finished)
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw MuxTestError.timedOut("payload then finish")
        }

        let result = try await #require(group.next())
        group.cancelAll()
        return result
    }
}

func expectNoIncomingStream(from stream: AsyncStream<MuxStream>) async {
    #expect(await incomingStreamObserved(from: stream) == false)
}

func expectResetFrame(
    in recorder: MuxFrameRecorder,
    streamID: UInt32,
    reason: ResetReason
) async throws {
    try await expectResetFrames(in: recorder, streamID: streamID, reason: reason, count: 1)
}

func expectResetFrames(
    in recorder: MuxFrameRecorder,
    streamID: UInt32,
    reason: ResetReason,
    count: Int
) async throws {
    let resets = await recorder.frames().filter { $0.flags == FrameFlags.reset.rawValue }
    #expect(resets.count == count)
    for reset in resets {
        #expect(reset.streamID == streamID)
        #expect(parseResetReason(from: reset.payload).reason == reason)
    }
}

func expectNoResetFrames(in recorder: MuxFrameRecorder) async {
    #expect(await recorder.frames().contains { $0.flags == FrameFlags.reset.rawValue } == false)
}

func assertSiblingRoundTrip(
    mux: Multiplexer,
    recorder: MuxFrameRecorder,
    sibling: MuxStream
) async throws {
    await recorder.reset()
    try await sibling.write(Data([0xa5]))
    let outboundData = try #require(await recorder.frames().first { $0.flags == FrameFlags.data.rawValue })
    #expect(outboundData.streamID == sibling.id)
    #expect(outboundData.payload == Data([0xa5]))

    try await mux.feedInbound(try encodeFrame(buildData(streamID: sibling.id, payload: Data([0x5a]))))
    #expect(try await readInboundPayload(from: sibling) == Data([0x5a]))
}

func assertIsolatedAndMuxSurvives(
    mux: Multiplexer,
    recorder: MuxFrameRecorder,
    isolated: MuxStream,
    sibling: MuxStream,
    expectedReason: ResetReason
) async throws {
    try await expectResetFrame(in: recorder, streamID: isolated.id, reason: expectedReason)

    var isolatedIterator = isolated.inbound.makeAsyncIterator()
    await expectMuxError(.transportClosed) {
        _ = try await isolatedIterator.next()
    }
    await expectMuxError(.writeAfterClose) {
        try await isolated.write(Data([0x01]))
    }

    try await assertSiblingRoundTrip(mux: mux, recorder: recorder, sibling: sibling)
}

@discardableResult
func conditionObserved(
    timeout: Duration = .milliseconds(100),
    pollInterval: Duration = .milliseconds(5),
    condition: @escaping @Sendable () async -> Bool
) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
        if await condition() {
            return true
        }
        try? await Task.sleep(for: pollInterval)
    }

    return false
}

@discardableResult
func waitUntil(
    _ description: String,
    timeout: Duration = .milliseconds(500),
    pollInterval: Duration = .milliseconds(5),
    condition: @escaping @Sendable () async -> Bool
) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
        if await condition() {
            return true
        }
        try? await Task.sleep(for: pollInterval)
    }

    Issue.record("Timed out waiting for \(description)")
    return false
}

func expectMuxError<T: Sendable>(
    _ expected: MuxError,
    operation: () async throws -> T
) async {
    do {
        _ = try await operation()
        Issue.record("Expected \(expected)")
    } catch let error as MuxError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), got \(error)")
    }
}

func expectFramingError<T: Sendable>(
    _ expected: FramingError,
    operation: () async throws -> T
) async {
    do {
        _ = try await operation()
        Issue.record("Expected \(expected)")
    } catch let error as FramingError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), got \(error)")
    }
}
