// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

enum BoundedHTTPError: Error, Equatable, Sendable {
    case timeout
    case bodyTooLarge
    case nonHTTPResponse
    case redirectRefused
}

enum BoundedHTTPClient {
    static let maxBodyBytes = 65536
    static let deadlineNanoseconds: UInt64 = 15_000_000_000

    static func send(
        request: URLRequest,
        session: URLSession,
        maxBodyBytes: Int = maxBodyBytes,
        deadlineNanoseconds: UInt64 = deadlineNanoseconds
    ) async throws -> (status: Int, data: Data, headers: [String: String]) {
        try await withThrowingTaskGroup(of: (status: Int, data: Data, headers: [String: String]).self) { group in
            defer { group.cancelAll() }
            group.addTask {
                let delegate = RedirectRefusingDelegate()
                let (bytes, response) = try await session.bytes(for: request, delegate: delegate)
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw BoundedHTTPError.nonHTTPResponse
                }
                let contentLength = httpResponse.expectedContentLength
                if contentLength > maxBodyBytes {
                    throw BoundedHTTPError.bodyTooLarge
                }
                var data = Data()
                data.reserveCapacity(contentLength > 0 ? Int(contentLength) : 4096)
                if contentLength != 0 {
                    for try await byte in bytes {
                        data.append(byte)
                        if data.count > maxBodyBytes {
                            throw BoundedHTTPError.bodyTooLarge
                        }
                        if contentLength > 0 && data.count >= contentLength {
                            break
                        }
                    }
                }
                var headers: [String: String] = [:]
                for (key, value) in httpResponse.allHeaderFields {
                    if let k = key as? String, let v = value as? String {
                        headers[k] = v
                    }
                }
                return (status: httpResponse.statusCode, data: data, headers: headers)
            }

            group.addTask {
                try await Task.sleep(nanoseconds: deadlineNanoseconds)
                throw BoundedHTTPError.timeout
            }

            let result = try await group.next()!
            return result
        }
    }
}

// why: URLSessionTaskDelegate callback bridge refusing all redirects across Swift 6 concurrency boundaries.
final class RedirectRefusingDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
