// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

enum HTTPStubResult: Sendable {
    case http(status: Int, data: Data, headers: [String: String] = [:])
    case nonHTTP(data: Data)
    case failure(any Error & Sendable)
}

final class HTTPStubProtocol: URLProtocol {
    static let state = HTTPStubProtocolState()

    override class func canInit(with _: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        do {
            let request = try Self.requestWithReadableBody(request)
            let result = try Self.state.respond(to: request)
            switch result {
            case .http(let status, let data, let headers):
                guard let url = request.url,
                      let response = HTTPURLResponse(
                          url: url,
                          statusCode: status,
                          httpVersion: "HTTP/1.1",
                          headerFields: headers
                      ) else {
                    client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
                    return
                }
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            case .nonHTTP(let data):
                guard let url = request.url else {
                    client?.urlProtocol(self, didFailWithError: URLError(.badURL))
                    return
                }
                let response = URLResponse(url: url, mimeType: "application/octet-stream", expectedContentLength: data.count, textEncodingName: nil)
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            case .failure(let error):
                client?.urlProtocol(self, didFailWithError: error)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    private static func requestWithReadableBody(_ request: URLRequest) throws -> URLRequest {
        guard request.httpBody == nil, let bodyStream = request.httpBodyStream else {
            return request
        }
        var copy = request
        copy.httpBody = try read(bodyStream)
        return copy
    }

    private static func read(_ stream: InputStream) throws -> Data {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count < 0 {
                throw stream.streamError ?? URLError(.cannotDecodeRawData)
            }
            if count == 0 {
                break
            }
            data.append(buffer, count: count)
        }
        return data
    }
}

final class HTTPStubProtocolState: @unchecked Sendable {
    // why: URLProtocol callbacks are synchronous framework entry points; NSLock guards test handler and request capture.
    private let lock = NSLock()
    private var handlers: [String: @Sendable (URLRequest) throws -> HTTPStubResult] = [:]
    private var capturedRequests: [String: [URLRequest]] = [:]

    var requests: [URLRequest] {
        lock.withLock { capturedRequests.values.flatMap { $0 } }
    }

    func requests(forHost host: String) -> [URLRequest] {
        lock.withLock { capturedRequests[host] ?? [] }
    }

    func reset(host: String? = nil) {
        lock.withLock {
            if let host {
                handlers.removeValue(forKey: host)
                capturedRequests.removeValue(forKey: host)
            } else {
                handlers.removeAll()
                capturedRequests.removeAll()
            }
        }
    }

    func setHandler(forHost host: String, _ handler: @escaping @Sendable (URLRequest) throws -> HTTPStubResult) {
        lock.withLock {
            handlers[host] = handler
            capturedRequests[host] = []
        }
    }

    func respond(to request: URLRequest) throws -> HTTPStubResult {
        guard let host = request.url?.host else {
            throw URLError(.badURL)
        }
        let handler = lock.withLock {
            capturedRequests[host, default: []].append(request)
            return handlers[host]
        }
        guard let handler else {
            throw URLError(.unsupportedURL)
        }
        return try handler(request)
    }
}

func makeHTTPStubSession(
    host: String,
    _ handler: @escaping @Sendable (URLRequest) throws -> HTTPStubResult
) -> URLSession {
    HTTPStubProtocol.state.setHandler(forHost: host, handler)
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [HTTPStubProtocol.self]
    return URLSession(configuration: configuration)
}
