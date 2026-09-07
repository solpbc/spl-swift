// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Synchronization
import Testing
@testable import SPLTunnel

@Suite("Bounded HTTP streaming", .serialized)
struct BoundedHTTPStreamingTests {
    @Test func slowProgressCannotExtendTotalDeadlineAndCancellationStopsLoading() async throws {
        let probe = ControlledHTTPStream(mode: .progress)
        let session = makeSession(probe)
        defer { session.invalidateAndCancel() }
        let start = ContinuousClock.now
        await #expect(throws: BoundedHTTPError.timeout) {
            try await BoundedHTTPClient.send(request: request(), session: session,
                maxBodyBytes: 1_048_576, deadlineNanoseconds: 150_000_000)
        }
        #expect(await probe.stopped())
        #expect(start.duration(to: .now) < .milliseconds(900))
        #expect(probe.chunkCount >= 2)
        #expect(!probe.watchdogFinished)
    }

    @Test func bodyStallAfterHeadersIsBoundedAndReleasesRequest() async throws {
        let probe = ControlledHTTPStream(mode: .stall)
        let session = makeSession(probe)
        defer { session.invalidateAndCancel() }
        let start = ContinuousClock.now
        await #expect(throws: BoundedHTTPError.timeout) {
            try await BoundedHTTPClient.send(request: request(), session: session, deadlineNanoseconds: 150_000_000)
        }
        #expect(await probe.stopped())
        #expect(start.duration(to: .now) < .milliseconds(900))
        #expect(probe.chunkCount == 1)
        #expect(!probe.watchdogFinished)
    }

    @Test func completeDeclaredBodyReturnsWithoutWaitingForPeerShutdown() async throws {
        let probe = ControlledHTTPStream(mode: .completeOpen)
        let session = makeSession(probe)
        defer { session.invalidateAndCancel() }
        let start = ContinuousClock.now
        let (status, body, _) = try await BoundedHTTPClient.send(
            request: request(), session: session, deadlineNanoseconds: 150_000_000)
        #expect(status == 200)
        #expect(body == Data(repeating: 65, count: 16_384))
        #expect(await probe.stopped())
        #expect(start.duration(to: .now) < .milliseconds(900))
        #expect(probe.chunkCount == 1)
        #expect(!probe.watchdogFinished)
    }

    @Test func oversizedOpenBodyRejectsAndCancelsUnderlyingRequest() async throws {
        let probe = ControlledHTTPStream(mode: .oversized)
        let session = makeSession(probe)
        defer { session.invalidateAndCancel() }
        let start = ContinuousClock.now
        await #expect(throws: BoundedHTTPError.bodyTooLarge) {
            try await BoundedHTTPClient.send(request: request(), session: session,
                maxBodyBytes: 4, deadlineNanoseconds: 150_000_000)
        }
        #expect(await probe.stopped())
        #expect(start.duration(to: .now) < .milliseconds(900))
        #expect(probe.chunkCount == 1)
        #expect(!probe.watchdogFinished)
    }

    private func request() -> URLRequest {
        URLRequest(url: URL(string: "https://streaming-control.test/response")!)
    }

    private func makeSession(_ probe: ControlledHTTPStream) -> URLSession {
        ControlledHTTPProtocol.current.withLock { $0 = probe }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ControlledHTTPProtocol.self]
        return URLSession(configuration: configuration)
    }
}

private final class ControlledHTTPProtocol: URLProtocol {
    static let current = Mutex<ControlledHTTPStream?>(nil)
    private let active = Mutex<ControlledHTTPStream?>(nil)

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let probe = Self.current.withLock { $0 }
        active.withLock { $0 = probe }
        probe?.attach(self)
    }
    override func stopLoading() { active.withLock { $0 }?.stop() }
}

// why: the recursive lock guards the URLProtocol callback bridge and timer state, including reentrant cancellation.
private final class ControlledHTTPStream: @unchecked Sendable {
    enum Mode { case progress, stall, completeOpen, oversized }
    private let lock = NSRecursiveLock()
    private let mode: Mode
    private var transport: URLProtocol?
    private var timer: (any DispatchSourceTimer)?
    private var ticks = 0
    private var chunks = 0
    private var finished = false
    private let stoppedEvents: AsyncStream<Bool>
    private let stoppedContinuation: AsyncStream<Bool>.Continuation

    init(mode: Mode) {
        self.mode = mode
        (stoppedEvents, stoppedContinuation) = AsyncStream.makeStream()
    }

    var chunkCount: Int { lock.withLock { chunks } }
    var watchdogFinished: Bool { lock.withLock { finished } }

    func stopped() async -> Bool {
        for await stopped in stoppedEvents { return stopped }
        return false
    }

    func attach(_ transport: URLProtocol) {
        lock.withLock {
            self.transport = transport
            let headers = mode == .completeOpen ? ["Content-Length": "16384"] : [:]
            let response = HTTPURLResponse(url: transport.request.url!, statusCode: 200,
                httpVersion: "HTTP/1.1", headerFields: headers)!
            let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "streaming-http-test"))
            timer.schedule(deadline: .now() + .milliseconds(10), repeating: .milliseconds(10))
            timer.setEventHandler { [weak self] in self?.tick() }
            self.timer = timer
            timer.resume()
            transport.client?.urlProtocol(transport, didReceive: response, cacheStoragePolicy: .notAllowed)
        }
    }

    private func emit(_ count: Int) {
        guard let transport else { return }
        chunks += 1
        transport.client?.urlProtocol(transport, didLoad: Data(repeating: 65, count: count))
    }

    private func tick() {
        lock.withLock {
            guard let transport else { return }
            ticks += 1
            if ticks >= 200 {
                // Bound a broken client's test without using peer shutdown as the success oracle.
                finished = true
                transport.client?.urlProtocolDidFinishLoading(transport)
                self.transport = nil
                timer?.cancel()
                timer = nil
                stoppedContinuation.yield(false)
                stoppedContinuation.finish()
            } else if ticks == 1 || mode == .progress {
                // AsyncBytes buffers URLProtocol delivery; complete chunks exercise the body reader before EOF.
                emit(16_384)
            }
        }
    }

    func stop() {
        lock.withLock {
            transport = nil
            timer?.cancel()
            timer = nil
            stoppedContinuation.yield(true)
            stoppedContinuation.finish()
        }
    }
}
