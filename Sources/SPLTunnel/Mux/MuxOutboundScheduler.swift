// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

/// Outbound mux frames share one injected `sink` that ultimately serializes on
/// `NWConnection`. Chunking at `MuxConstants.recommendedChunk` (64 KB) already
/// bounds a single `MuxStream.write` so a control frame is not stuck behind one
/// multi-megabyte payload, but it does not reorder frames that concurrent
/// streams have already handed to `sink`. `proto/framing.md` requires a PONG
/// reply to be treated as higher priority than queued DATA; a two-queue
/// scheduler is the smallest mechanism that actually reorders.
///
/// An in-flight `sink` call cannot be preempted: `NWConnection.send` is already
/// underway. The drain therefore finishes the current call, then exhausts every
/// queued `.control` frame before the next `.data` frame. Both keepalive PING
/// (the client's own probe) and PONG (the peer's reply) use `.control` so
/// promptness is not limited to the reply path. MuxStream DATA/WINDOW/CLOSE
/// stay `.data` so `MuxStream.swift` is unchanged.
///
/// `send` suspends until this specific frame has been given to the real `sink`
/// and that call has returned or thrown, preserving `MuxStream.write`'s
/// per-chunk backpressure.
actor MuxOutboundScheduler {
    enum Priority: Sendable {
        case control
        case data
    }

    private struct Item: Sendable {
        let frame: Data
        let priority: Priority
        let continuation: CheckedContinuation<Void, Error>
    }

    private let sink: @Sendable (Data) async throws -> Void
    private var control: [Item] = []
    private var data: [Item] = []
    private var tornDown = false
    private var dataInFlight = false
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []
    private var drainTask: Task<Void, Never>?

    init(sink: @escaping @Sendable (Data) async throws -> Void) {
        self.sink = sink
    }

    func send(_ frame: Data, priority: Priority) async throws {
        self.ensureDrain()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            if self.tornDown {
                continuation.resume(throwing: MuxError.transportClosed)
                return
            }
            let item = Item(frame: frame, priority: priority, continuation: continuation)
            switch priority {
            case .control:
                self.control.append(item)
            case .data:
                self.data.append(item)
            }
            self.wakeDrain()
        }
    }

    func dataInFlightOrQueued() -> Bool {
        self.dataInFlight || !self.data.isEmpty
    }

    func tearDown() {
        self.tornDown = true
        let parked = self.control + self.data
        self.control.removeAll()
        self.data.removeAll()
        self.dataInFlight = false
        for item in parked {
            item.continuation.resume(throwing: MuxError.transportClosed)
        }
        self.wakeDrain()
        self.drainTask?.cancel()
        self.drainTask = nil
    }

    private func ensureDrain() {
        guard self.drainTask == nil, !self.tornDown else {
            return
        }
        self.drainTask = Task { await self.runDrainLoop() }
    }

    private func wakeDrain() {
        let waiters = self.drainWaiters
        self.drainWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func runDrainLoop() async {
        while !Task.isCancelled {
            if self.tornDown {
                return
            }
            if self.control.isEmpty && self.data.isEmpty {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    if self.tornDown || !self.control.isEmpty || !self.data.isEmpty {
                        continuation.resume()
                    } else {
                        self.drainWaiters.append(continuation)
                    }
                }
                continue
            }

            let item: Item
            if let next = self.control.first {
                self.control.removeFirst()
                item = next
                self.dataInFlight = false
            } else if let next = self.data.first {
                self.data.removeFirst()
                item = next
                self.dataInFlight = true
            } else {
                continue
            }

            do {
                try await self.sink(item.frame)
                self.dataInFlight = false
                item.continuation.resume()
            } catch {
                self.dataInFlight = false
                item.continuation.resume(throwing: error)
            }
        }
    }
}
