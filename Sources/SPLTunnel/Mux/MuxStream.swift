// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

enum MuxConstants {
    static let initialCredit: UInt32 = 1 << 20
    static let maxConcurrentStreams: Int = 256
    static let recommendedChunk: Int = 64 << 10
    static let windowGrantThreshold: Int = 64 << 10
}

public enum StreamState: Sendable, Equatable {
    case open
    case halfClosedLocal
    case halfClosedRemote
    case closed
    case resetLocal
    case resetRemote
}

enum InboundDataOutcome: Equatable, Sendable {
    case accepted
    case receiveWindowExceeded
}

enum SendCreditOutcome: Equatable, Sendable {
    case accepted
    case flowControlExceeded
}

private enum CreditWaiterSlot {
    case pending
    case installed(CheckedContinuation<Void, Error>)
    case cancelled
}

public final actor MuxStream {
    public nonisolated let id: UInt32
    public nonisolated var inbound: MuxInboundSequence {
        MuxInboundSequence(stream: inboundStream) { [self] byteCount in
            try await self.noteInboundConsumed(byteCount)
        }
    }
    public private(set) var state: StreamState

    private let sink: @Sendable (Data) async throws -> Void
    private let onTerminal: @Sendable (UInt32) async -> Void
    private nonisolated let inboundStream: AsyncThrowingStream<Data, Error>
    private let inboundContinuation: AsyncThrowingStream<Data, Error>.Continuation
    private var inboundFinished = false
    private var didNotifyTerminal = false
    private var sendCredit = Int(MuxConstants.initialCredit)
    private var receiveWindow = Int(MuxConstants.initialCredit)
    private var consumedSinceLastGrant = 0
    private var queuedInboundBytes = 0
    private var nextCreditWaiterID: UInt64 = 1
    private var creditWaiters: [UInt64: CreditWaiterSlot] = [:]

    init(
        id: UInt32,
        state: StreamState = .open,
        sink: @escaping @Sendable (Data) async throws -> Void,
        onTerminal: @escaping @Sendable (UInt32) async -> Void
    ) {
        self.id = id
        self.state = state
        self.sink = sink
        self.onTerminal = onTerminal

        var continuation: AsyncThrowingStream<Data, Error>.Continuation!
        let inboundStream = AsyncThrowingStream<Data, Error> { continuation = $0 }
        self.inboundStream = inboundStream
        self.inboundContinuation = continuation
    }

    deinit {
        inboundContinuation.finish()
    }

    public func write(_ payload: Data) async throws {
        var offset = 0
        while offset < payload.count {
            let count = min(MuxConstants.recommendedChunk, payload.count - offset)
            try await waitForCredit(count)

            let chunk = Data(payload[offset..<(offset + count)])
            let frame = try encodeFrame(buildData(streamID: id, payload: chunk))
            try await sink(frame)
            offset += count
        }

        if payload.isEmpty {
            try ensureWritable()
            let frame = try encodeFrame(buildData(streamID: id, payload: Data()))
            try await sink(frame)
        }
    }

    public func close() async throws {
        try ensureWritable()
        let frame = try encodeFrame(buildClose(streamID: id))
        try await sink(frame)

        switch state {
        case .open:
            state = .halfClosedLocal
        case .halfClosedRemote:
            state = .closed
            finishInbound(nil)
            resumeCreditWaiters(returning: ())
            await notifyTerminal()
        case .halfClosedLocal, .closed, .resetLocal, .resetRemote:
            throw MuxError.writeAfterClose
        }
    }

    public func reset(reason: ResetReason) async {
        guard await markResetLocal() else { return }
        let frame = buildReset(streamID: id, reason: reason)
        if let data = try? encodeFrame(frame) {
            try? await sink(data)
        }
    }

    func markResetLocal() async -> Bool {
        guard state != .resetLocal && state != .resetRemote && state != .closed else {
            return false
        }

        state = .resetLocal
        finishInbound(MuxError.transportClosed)
        resumeCreditWaiters(throwing: MuxError.writeAfterClose)
        await notifyTerminal()
        return true
    }

    func deliverInboundData(_ payload: Data) -> InboundDataOutcome {
        guard state == .open || state == .halfClosedLocal else {
            return .accepted
        }
        guard payload.count <= receiveWindow else {
            return .receiveWindowExceeded
        }

        receiveWindow -= payload.count
        queuedInboundBytes += payload.count
        inboundContinuation.yield(payload)
        return .accepted
    }

    func admitInitialPayload(_ payload: Data) -> InboundDataOutcome {
        guard payload.count <= receiveWindow else {
            return .receiveWindowExceeded
        }

        receiveWindow -= payload.count
        queuedInboundBytes += payload.count
        inboundContinuation.yield(payload)
        return .accepted
    }

    func deliverInboundClose() async {
        switch state {
        case .open:
            state = .halfClosedRemote
            finishInbound(nil)
        case .halfClosedLocal:
            state = .closed
            finishInbound(nil)
            resumeCreditWaiters(throwing: MuxError.writeAfterClose)
            await notifyTerminal()
        case .halfClosedRemote, .closed, .resetLocal, .resetRemote:
            finishInbound(nil)
        }
    }

    func deliverInboundReset(reason: ResetReason, rawByte: UInt8) async {
        guard state != .closed && state != .resetLocal && state != .resetRemote else {
            return
        }
        state = .resetRemote
        finishInbound(MuxError.streamReset(streamID: id, reason: reason, rawByte: rawByte))
        resumeCreditWaiters(throwing: MuxError.writeAfterClose)
        await notifyTerminal()
    }

    func grantSendCredit(_ credit: UInt32) -> SendCreditOutcome {
        let updated = sendCredit + Int(credit)
        guard updated <= Int(Int32.max) else {
            return .flowControlExceeded
        }

        sendCredit = updated
        resumeCreditWaiters(returning: ())
        return .accepted
    }

    func tearDown(reason: TearDownReason) {
        state = .closed
        switch reason {
        case .normalShutdown:
            finishInbound(nil)
        case .transportFailure, .protocolError:
            finishInbound(MuxError.transportClosed)
        }
        resumeCreditWaiters(throwing: MuxError.writeAfterClose)
    }

    func queuedInboundByteCount() -> Int {
        queuedInboundBytes
    }

    func noteInboundConsumed(_ byteCount: Int) async throws {
        guard byteCount > 0 else {
            return
        }

        queuedInboundBytes = max(0, queuedInboundBytes - byteCount)
        consumedSinceLastGrant += byteCount
        guard consumedSinceLastGrant >= MuxConstants.windowGrantThreshold else {
            return
        }
        guard canEmitWindowGrant else {
            consumedSinceLastGrant = 0
            return
        }
        try await emitWindowGrant()
    }

    private var canEmitWindowGrant: Bool {
        !inboundFinished && state != .closed && state != .resetLocal && state != .resetRemote
    }

    private func waitForCredit(_ byteCount: Int) async throws {
        while sendCredit < byteCount {
            try ensureWritable()
            try Task.checkCancellation()
            let id = nextCreditWaiterID
            nextCreditWaiterID &+= 1
            prepareCreditWaiter(id: id)
            try await withTaskCancellationHandler {
                try await installCreditWaiter(id: id)
            } onCancel: { [weak self] in
                Task { [weak self] in
                    await self?.cancelCreditWaiter(id: id)
                }
            }
            try Task.checkCancellation()
        }

        try ensureWritable()
        sendCredit -= byteCount
    }

    func prepareCreditWaiter(id: UInt64) {
        creditWaiters[id] = .pending
    }

    func installCreditWaiter(id: UInt64) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            switch creditWaiters[id] {
            case .pending:
                creditWaiters[id] = .installed(continuation)
            case .cancelled:
                creditWaiters.removeValue(forKey: id)
                continuation.resume(throwing: CancellationError())
            case .installed, nil:
                continuation.resume(returning: ())
            }
        }
    }

    func cancelCreditWaiter(id: UInt64) {
        switch creditWaiters[id] {
        case .pending:
            creditWaiters[id] = .cancelled
        case let .installed(waiter):
            // Removal from creditWaiters is the resume token; no path resumes twice.
            creditWaiters.removeValue(forKey: id)
            waiter.resume(throwing: CancellationError())
        case .cancelled, nil:
            return
        }
    }

    private func ensureWritable() throws {
        switch state {
        case .open, .halfClosedRemote:
            return
        case .halfClosedLocal, .closed, .resetLocal, .resetRemote:
            throw MuxError.writeAfterClose
        }
    }

    private func emitWindowGrant() async throws {
        let grant = consumedSinceLastGrant
        guard grant > 0 else {
            return
        }

        consumedSinceLastGrant = 0
        receiveWindow += grant
        let frame = try encodeFrame(buildWindow(streamID: id, credit: UInt32(grant)))
        try await sink(frame)
    }

    private func finishInbound(_ error: Error?) {
        guard !inboundFinished else {
            return
        }

        inboundFinished = true
        if let error {
            inboundContinuation.finish(throwing: error)
        } else {
            inboundContinuation.finish()
        }
    }

    private func notifyTerminal() async {
        guard !didNotifyTerminal else {
            return
        }
        didNotifyTerminal = true
        await onTerminal(id)
    }

    private func resumeCreditWaiters(returning value: Void) {
        let waiters = creditWaiters
        creditWaiters.removeAll()
        for (_, slot) in waiters {
            if case let .installed(waiter) = slot {
                // Removal from creditWaiters is the resume token; no path resumes twice.
                waiter.resume(returning: value)
            }
        }
    }

    private func resumeCreditWaiters(throwing error: Error) {
        let waiters = creditWaiters
        creditWaiters.removeAll()
        for (_, slot) in waiters {
            if case let .installed(waiter) = slot {
                // Removal from creditWaiters is the resume token; no path resumes twice.
                waiter.resume(throwing: error)
            }
        }
    }
}
