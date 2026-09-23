// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("LoopbackCapability")
struct LoopbackCapabilityTests {
    private let capability = LoopbackCapability(token: "0123456789abcdef0123456789abcdef")

    private func head(_ headers: [String]) -> Data {
        Data((["GET /app/home HTTP/1.1", "Host: 127.0.0.1:50000"] + headers + ["", ""]).joined(separator: "\r\n").utf8)
    }

    @Test func theProcessCapabilityIsStableRandomAndRedacted() {
        let process = LoopbackCapability.process
        #expect(process == LoopbackCapability.process)
        #expect(process.token.count == 32)
        #expect(process.token.allSatisfy { $0.isHexDigit })
        #expect(process.token != String(repeating: "0", count: 32))
        #expect(!String(describing: process).contains(process.token))
        #expect(process.cookieHeaderValue == "spl_loopback=\(process.token)")
    }

    @Test func theWebViewCookieIsHostOnlySessionAndHTTPOnly() throws {
        let cookie = try #require(capability.httpCookie())
        #expect(cookie.name == "spl_loopback")
        #expect(cookie.value == capability.token)
        #expect(cookie.domain == "127.0.0.1")
        #expect(cookie.path == "/")
        #expect(cookie.isSessionOnly)
        #expect(cookie.isHTTPOnly)
    }

    @Test(arguments: [
        ["Cookie: spl_loopback=0123456789abcdef0123456789abcdef"],
        ["cookie: theme=dark; spl_loopback=0123456789abcdef0123456789abcdef; other=1"],
        ["COOKIE:spl_loopback=0123456789abcdef0123456789abcdef"],
        ["Cookie: theme=dark", "Cookie: spl_loopback=0123456789abcdef0123456789abcdef"],
        ["Cookie: spl_loopback=wrong", "Cookie: spl_loopback=0123456789abcdef0123456789abcdef"],
    ])
    func theRightCookieIsAdmitted(headers: [String]) {
        #expect(capability.admission(of: head(headers)) == .admitted)
    }

    @Test(arguments: [
        [String](),
        ["Cookie: theme=dark"],
        ["Cookie: xspl_loopback=0123456789abcdef0123456789abcdef"],
        ["X-Cookie: spl_loopback=0123456789abcdef0123456789abcdef"],
        ["X-SPL-Loopback: 0123456789abcdef0123456789abcdef"],
    ])
    func aHeadWithoutTheCookieIsRefusedAsMissing(headers: [String]) {
        #expect(capability.admission(of: head(headers)) == .refused(.missing))
    }

    @Test(arguments: [
        "Cookie: spl_loopback=",
        "Cookie: spl_loopback=0123456789abcdef0123456789abcdee",
        "Cookie: spl_loopback=0123456789abcdef0123456789abcdef0",
        "Cookie: spl_loopback=0123456789abcdef0123456789abcde",
        "Cookie: spl_loopback=x0123456789abcdef0123456789abcdef",
        "Cookie: spl_loopback=0123456789ABCDEF0123456789ABCDEF",
    ])
    func aWrongValueIsRefusedAsMismatch(header: String) {
        #expect(capability.admission(of: head([header])) == .refused(.mismatch))
    }

    @Test func theCookieInTheRequestBodyDoesNotAdmit() {
        var request = head(["Content-Length: 52"])
        request.append(Data("Cookie: spl_loopback=0123456789abcdef0123456789abcdef".utf8))
        #expect(capability.admission(of: request) == .refused(.missing))
    }

    @Test func aPartialHeadWaitsForMoreBytes() {
        let full = head(["Cookie: spl_loopback=0123456789abcdef0123456789abcdef"])
        for cut in [0, 1, 20, full.count - 1] {
            #expect(capability.admission(of: full.prefix(cut)) == .incomplete)
        }
    }

    @Test func everyPrefixOfAValidHeadWaitsAndOnlyTheWholeHeadIsAdmitted() {
        // Covers every split point, including each inside `\r\n\r\n`,
        // independent of how the socket happens to deliver the bytes.
        let full = head(["Cookie: spl_loopback=0123456789abcdef0123456789abcdef"])
        for cut in 0..<full.count {
            #expect(capability.admission(of: full.prefix(cut)) == .incomplete, "prefix \(cut)")
        }
        #expect(capability.admission(of: full) == .admitted)
    }

    @Test func theBoundIsOnTheHeadNotOnTheBytesRead() {
        // A head and a large body often arrive in one read. Bounding the bytes
        // read instead of the head would refuse every large upload.
        var request = head(["Cookie: spl_loopback=0123456789abcdef0123456789abcdef", "Content-Length: 49152"])
        request.append(Data(repeating: 0x5A, count: 48 * 1024))
        #expect(capability.admission(of: request) == .admitted)

        let unterminated = Data(repeating: 0x41, count: LoopbackCapability.maxRequestHeadBytes + 1)
        #expect(capability.admission(of: unterminated) == .refused(.oversize))
    }

    @Test func aHeadPastTheBoundIsRefusedWithOrWithoutATerminator() {
        let padding = "X-Pad: " + String(repeating: "a", count: LoopbackCapability.maxRequestHeadBytes)
        let unterminated = Data(("GET / HTTP/1.1\r\n" + padding).utf8)
        #expect(capability.admission(of: unterminated) == .refused(.oversize))
        let terminated = head([padding, "Cookie: spl_loopback=0123456789abcdef0123456789abcdef"])
        #expect(capability.admission(of: terminated) == .refused(.oversize))
    }
}
