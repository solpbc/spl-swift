// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public struct MuxInboundSequence: AsyncSequence, Sendable {
    public typealias Element = Data

    private let stream: AsyncThrowingStream<Data, Error>
    private let didConsume: @Sendable (Int) async throws -> Void

    init(
        stream: AsyncThrowingStream<Data, Error>,
        didConsume: @escaping @Sendable (Int) async throws -> Void
    ) {
        self.stream = stream
        self.didConsume = didConsume
    }

    public func makeAsyncIterator() -> Iterator {
        Iterator(iterator: stream.makeAsyncIterator(), didConsume: didConsume)
    }

    public struct Iterator: AsyncIteratorProtocol {
        private var iterator: AsyncThrowingStream<Data, Error>.Iterator
        private let didConsume: @Sendable (Int) async throws -> Void

        init(
            iterator: AsyncThrowingStream<Data, Error>.Iterator,
            didConsume: @escaping @Sendable (Int) async throws -> Void
        ) {
            self.iterator = iterator
            self.didConsume = didConsume
        }

        public mutating func next() async throws -> Data? {
            guard let payload = try await iterator.next() else {
                return nil
            }
            // Credit is returned at hand-off: the bytes have left the internal queue.
            try await didConsume(payload.count)
            return payload
        }
    }
}
