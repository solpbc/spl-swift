// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

/// Proof that a loopback client is this app rather than another process on
/// the same machine.
///
/// The proxy listens on `127.0.0.1`, which every process on the host can reach:
/// another app, or a web page in any browser. Whatever it forwards reaches the
/// journal as the paired device, and a paired device is the owner. So the proxy
/// admits a connection only when its first request carries this capability as a
/// cookie. A cookie is the one carrier WebKit attaches to every request a page
/// makes without changing its URL; URLSession callers attach the same cookie
/// explicitly.
///
/// The token is random, held in memory for the life of the process, and never
/// persisted or logged.
public struct LoopbackCapability: Sendable, Equatable, CustomStringConvertible {
    /// The cookie name the proxy looks for.
    public static let cookieName = "spl_loopback"

    /// This process's capability, generated on first use.
    public static let process = LoopbackCapability(token: randomToken())

    /// The largest request head the proxy reads while looking for the cookie.
    static let maxRequestHeadBytes = 16 * 1024

    let token: String

    init(token: String) {
        self.token = token
    }

    /// The `Cookie` header value a URLSession request to the proxy carries.
    public var cookieHeaderValue: String {
        "\(Self.cookieName)=\(token)"
    }

    /// The cookie a web view's cookie store holds so its pages carry the
    /// capability on every request to `host`.
    public func httpCookie(host: String = "127.0.0.1") -> HTTPCookie? {
        HTTPCookie(properties: [
            .name: Self.cookieName,
            .value: token,
            .domain: host,
            .path: "/",
            .sameSitePolicy: HTTPCookieStringPolicy.sameSiteLax.rawValue,
            HTTPCookiePropertyKey("HttpOnly"): "TRUE",
        ])
    }

    // Never the token: a capability that reaches a log line is a capability
    // anyone who can read the log holds.
    public var description: String {
        "LoopbackCapability(redacted)"
    }

    private static func randomToken() -> String {
        var generator = SystemRandomNumberGenerator()
        return (0..<16)
            .map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator)) }
            .joined()
    }
}

enum LoopbackRefusal: String, Sendable, Equatable {
    /// No `spl_loopback` cookie in the request head.
    case missing
    /// An `spl_loopback` cookie with the wrong value.
    case mismatch
    /// No complete request head within `maxRequestHeadBytes`.
    case oversize
}

enum LoopbackAdmission: Sendable, Equatable {
    /// More bytes are needed before the head is complete.
    case incomplete
    case admitted
    case refused(LoopbackRefusal)
}

extension LoopbackCapability {
    /// Judges the bytes a connection has sent so far.
    ///
    /// Only the first request's head is examined: nothing but the process that
    /// opened a TCP connection can write into it, so a connection admitted once
    /// stays admitted for its keep-alive requests and any upgrade.
    func admission(of buffered: Data) -> LoopbackAdmission {
        let terminator = Data("\r\n\r\n".utf8)
        guard let end = buffered.range(of: terminator) else {
            return buffered.count > Self.maxRequestHeadBytes ? .refused(.oversize) : .incomplete
        }
        let headLength = end.lowerBound - buffered.startIndex
        guard headLength <= Self.maxRequestHeadBytes else {
            return .refused(.oversize)
        }

        let head = String(decoding: buffered[buffered.startIndex..<end.lowerBound], as: UTF8.self)
        var sawCookie = false
        // The first line is the request line; headers follow.
        for line in head.components(separatedBy: "\r\n").dropFirst() {
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "cookie" else {
                continue
            }
            for pair in line[line.index(after: colon)...].split(separator: ";") {
                let trimmed = pair.trimmingCharacters(in: .whitespaces)
                guard let equals = trimmed.firstIndex(of: "="),
                      trimmed[..<equals] == Self.cookieName else {
                    continue
                }
                sawCookie = true
                if Self.constantTimeEqual(trimmed[trimmed.index(after: equals)...], token) {
                    return .admitted
                }
            }
        }
        return .refused(sawCookie ? .mismatch : .missing)
    }

    private static func constantTimeEqual(_ candidate: Substring, _ expected: String) -> Bool {
        let lhs = Array(candidate.utf8)
        let rhs = Array(expected.utf8)
        guard lhs.count == rhs.count else {
            return false
        }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}
