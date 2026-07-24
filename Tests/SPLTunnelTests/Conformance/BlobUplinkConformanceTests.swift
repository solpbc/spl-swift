// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("BlobUplinkConformance")
struct BlobUplinkConformanceTests {
    @Test func nativeSessionDialDoesNotOfferBrowserSubprotocolCarrier() throws {
        // proto/blob-uplink.md:24-28,38 and proto/pair-window.md:81 native dial uses no browser subprotocol carrier.
        let request = try RelayWSTransport.makeRequest(
            endpoint: URL(string: "https://link.solstone.app")!,
            path: "session/dial",
            credential: .session(instanceID: "instance", authToken: "token"),
            clientInfo: SPLClientInfo(userAgent: "spl-swift-tests/1")
        )

        #expect(request.url?.absoluteString == "wss://link.solstone.app/session/dial?instance=instance")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token")
        #expect(request.value(forHTTPHeaderField: "Sec-WebSocket-Protocol") == nil)
    }
}
