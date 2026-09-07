// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let boundedTestHost = "bounded-http.test"

@Suite("BoundedHTTPClient", .serialized)
struct BoundedHTTPClientTests {
    @Test func sendCollectsBodyWithinLimit() async throws {
        defer { HTTPStubProtocol.state.reset(host: boundedTestHost) }
        let session = makeHTTPStubSession(host: boundedTestHost) { _ in
            .http(status: 200, data: Data("hello world".utf8))
        }

        let request = URLRequest(url: URL(string: "https://\(boundedTestHost)/test")!)
        let (status, data, _) = try await BoundedHTTPClient.send(
            request: request,
            session: session,
            maxBodyBytes: 1024
        )

        #expect(status == 200)
        #expect(String(data: data, encoding: .utf8) == "hello world")
    }

    @Test func sendThrowsWhenBodyExceedsCap() async throws {
        defer { HTTPStubProtocol.state.reset(host: boundedTestHost) }
        let largeData = Data(repeating: 0x41, count: 2000)
        let session = makeHTTPStubSession(host: boundedTestHost) { _ in
            .http(status: 200, data: largeData)
        }

        let request = URLRequest(url: URL(string: "https://\(boundedTestHost)/test")!)
        await #expect(throws: BoundedHTTPError.bodyTooLarge) {
            try await BoundedHTTPClient.send(
                request: request,
                session: session,
                maxBodyBytes: 1000
            )
        }
    }

    @Test func redirectRefusingDelegatePreventsRedirectFollowing() async throws {
        let delegate = RedirectRefusingDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let request = URLRequest(url: URL(string: "https://target.test")!)
        let httpResponse = HTTPURLResponse(
            url: URL(string: "https://initial.test")!,
            statusCode: 302,
            httpVersion: "HTTP/1.1",
            headerFields: ["Location": "https://target.test"]
        )!
        let task = session.dataTask(with: request)

        let disposition = await withCheckedContinuation { continuation in
            delegate.urlSession(session, task: task, willPerformHTTPRedirection: httpResponse, newRequest: request) { nextRequest in
                continuation.resume(returning: nextRequest)
            }
        }
        #expect(disposition == nil)
    }

    @Test func sendTimesOutWhenServerHangs() async throws {
        defer { HTTPStubProtocol.state.reset(host: boundedTestHost) }
        let session = makeHTTPStubSession(host: boundedTestHost) { _ in
            .hang
        }

        let request = URLRequest(url: URL(string: "https://\(boundedTestHost)/hang")!)
        await #expect(throws: BoundedHTTPError.timeout) {
            try await BoundedHTTPClient.send(
                request: request,
                session: session,
                deadlineNanoseconds: 50_000_000 // 50ms
            )
        }
    }

    @Test func sendRefusesRedirectAndReturns302WithoutFollowing() async throws {
        defer { HTTPStubProtocol.state.reset(host: boundedTestHost) }
        let session = makeHTTPStubSession(host: boundedTestHost) { _ in
            .http(status: 302, data: Data("redirected".utf8), headers: ["Location": "https://\(boundedTestHost)/target"])
        }

        let request = URLRequest(url: URL(string: "https://\(boundedTestHost)/initial")!)
        let (status, data, _) = try await BoundedHTTPClient.send(
            request: request,
            session: session
        )

        #expect(status == 302)
        #expect(String(data: data, encoding: .utf8) == "redirected")
        #expect(HTTPStubProtocol.state.requests(forHost: boundedTestHost).count == 1)
    }
}
