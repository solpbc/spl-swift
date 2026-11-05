// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Testing
@testable import SPLTunnel

/// A web view's origin is `http://127.0.0.1:<port>`, so a proxy rebuilt on the
/// same port keeps the page's HTTP cache and storage. These pin when the
/// preferred port is kept and how the proxy reports when it is not.
@Suite("LoopbackProxy preferred port", .serialized)
struct LoopbackProxyPreferredPortTests {
    private static let request = Data("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: \(loopbackTestCapability.cookieHeaderValue)\r\n\r\n".utf8)
    private static let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".utf8)

    private static func makeProxy(preferredPortAttempt: Duration = LoopbackProxy.defaultPreferredPortAttempt) -> LoopbackProxy {
        LoopbackProxy(
            opener: AnsweringLoopbackOpener(response: response),
            capability: loopbackTestCapability,
            preferredPortAttempt: preferredPortAttempt
        )
    }

    @Test func aStoppedProxysPortIsBoundAgainByTheNextProxy() async throws {
        let first = Self.makeProxy()
        let port = try await first.start()
        #expect(try await Self.roundTrip(port: port) == Self.response)
        await first.stop()

        // A reconnect: the next proxy asks for the port the last one had.
        for _ in 0..<5 {
            let next = Self.makeProxy()
            let binding = try await next.start(preferredPort: port)
            #expect(binding == LoopbackBinding(port: port, fallback: nil))
            #expect(try await Self.roundTrip(port: port) == Self.response)
            await next.stop()
        }
    }

    @Test func thePortIsBoundAgainWhileTheOldProxyHadOpenConnections() async throws {
        // A page holds event streams and idle keep-alive connections open; the
        // proxy closes them on stop, and the next proxy still gets the port.
        let first = Self.makeProxy()
        let port = try await first.start()
        let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
        var held: [NWConnection] = []
        defer { for client in held { client.cancel() } }
        for _ in 0..<3 {
            let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
            held.append(client)
            try await startAndReturnReadyWaiter(client).wait()
        }
        #expect(await waitUntil("held connections accepted") {
            await first.connectionTaskCount() == 3
        })
        await first.stop()

        let next = Self.makeProxy()
        let binding = try await next.start(preferredPort: port)
        #expect(binding == LoopbackBinding(port: port, fallback: nil))
        #expect(try await Self.roundTrip(port: port) == Self.response)
        await next.stop()
    }

    @Test func aPreferredPortInUseFallsBackToAnotherPortAndSaysSo() async throws {
        let holder = Self.makeProxy()
        let held = try await holder.start()

        let proxy = Self.makeProxy(preferredPortAttempt: .milliseconds(300))
        let started = ContinuousClock.now
        let binding = try await proxy.start(preferredPort: held)
        #expect(binding.port != held)
        #expect(binding.fallback == .preferredPortInUse)
        // It kept trying for the preferred attempt before falling back.
        #expect(started.duration(to: .now) >= .milliseconds(300))
        #expect(try await Self.roundTrip(port: binding.port) == Self.response)
        // Asking again returns the binding it has, fallback reason included.
        #expect(try await proxy.start(preferredPort: held) == binding)
        #expect(try await proxy.start() == binding.port)
        await proxy.stop()
        await holder.stop()
    }

    @Test func aSecondListenerCannotTakeThePortWhileTheProxyHoldsIt() async throws {
        // Every app on an iPhone runs as the same user, so nothing but the
        // bind itself keeps another listener off a port the proxy holds.
        let proxy = Self.makeProxy()
        let port = try await proxy.start(preferredPort: nil).port
        for reuse in [false, true] {
            let parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = reuse
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: try #require(NWEndpoint.Port(rawValue: port)))
            let squatter = try NWListener(using: parameters)
            let outcome = AsyncResultBox<String>()
            squatter.newConnectionHandler = { $0.cancel() }
            squatter.stateUpdateHandler = { state in
                switch state {
                case .ready: Task { await outcome.store("ready") }
                case .failed(let error): Task { await outcome.store("failed: \(error)") }
                default: break
                }
            }
            squatter.start(queue: .global())
            #expect(await waitUntil("second listener settles", timeout: .seconds(2)) {
                await outcome.snapshot() != nil
            })
            let settled = await outcome.snapshot() ?? "nil"
            #expect(settled.hasPrefix("failed"), "allowLocalEndpointReuse \(reuse): \(settled)")
            squatter.cancel()
        }
        #expect(try await Self.roundTrip(port: port) == Self.response)
        await proxy.stop()
    }

    @Test func aPreferredPortProxyStillRefusesAConnectionWithoutTheCapability() async throws {
        let first = Self.makeProxy()
        let port = try await first.start()
        await first.stop()

        let proxy = Self.makeProxy()
        #expect(try await proxy.start(preferredPort: port) == LoopbackBinding(port: port, fallback: nil))
        let client = NWConnection(host: "127.0.0.1", port: try #require(NWEndpoint.Port(rawValue: port)), using: .tcp)
        defer { client.cancel() }
        try await startAndReturnReadyWaiter(client).wait()
        try await LoopbackProxy.send(Data("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".utf8), to: client)
        let response = String(decoding: try await Self.readSome(from: client), as: UTF8.self)
        #expect(response.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
        #expect(response.contains("\r\nX-SPL-Loopback-Refused: "))
        client.cancel()
        await proxy.stop()
    }

    @Test func noPreferredPortBehavesAsBefore() async throws {
        let proxy = Self.makeProxy()
        let binding = try await proxy.start(preferredPort: nil)
        #expect(binding.fallback == nil)
        #expect(binding.port != 0)
        #expect(try await proxy.start() == binding.port)
        await proxy.stop()
    }

    // MARK: helpers

    /// One admitted request, half-closed; returns everything the proxy sent back.
    private static func roundTrip(port: UInt16) async throws -> Data {
        let client = NWConnection(host: "127.0.0.1", port: try #require(NWEndpoint.Port(rawValue: port)), using: .tcp)
        defer { client.cancel() }
        try await startAndReturnReadyWaiter(client).wait()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            client.send(content: request, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
        var collected = Data()
        while true {
            let (chunk, isComplete) = try await LoopbackProxy.receive(from: client)
            if let chunk { collected.append(chunk) }
            if isComplete || chunk == nil { return collected }
        }
    }

    private static func readSome(from client: NWConnection) async throws -> Data {
        var collected = Data()
        while !collected.contains(Data("\r\n\r\n".utf8)) {
            let (chunk, isComplete) = try await LoopbackProxy.receive(from: client)
            if let chunk { collected.append(chunk) }
            if isComplete || chunk == nil { break }
        }
        return collected
    }
}

/// Answers each stream with a fixed response once the client half-closes.
private actor AnsweringLoopbackOpener: MuxStreamOpening {
    private let response: Data
    private var attempts = 0
    private var streams: [UInt32: MuxStream] = [:]
    private var decoder = FrameDecoder()

    init(response: Data) {
        self.response = response
    }

    func openStream() async throws -> MuxStream {
        attempts += 1
        let id = UInt32(attempts * 2 - 1)
        let stream = MuxStream(
            id: id,
            sink: { bytes in try await self.acceptOutbound(bytes) },
            onTerminal: { id in await self.removeStream(id) }
        )
        streams[id] = stream
        return stream
    }

    private func removeStream(_ id: UInt32) { streams[id] = nil }

    private func acceptOutbound(_ bytes: Data) async throws {
        decoder.feed(bytes)
        while let frame = try decoder.next() {
            if frame.flags == FrameFlags.close.rawValue, let stream = streams[frame.streamID] {
                _ = await stream.deliverInboundData(response)
                await stream.deliverInboundClose()
            }
        }
    }
}
