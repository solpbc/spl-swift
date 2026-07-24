// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let dialClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")

@Suite("DialClient", .serialized)
struct DialClientTests {
    @Test func lanConnectsSendsAndReceivesBytesThroughTCPEcho() async throws {
        let server = TCPEchoServer()
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dial(
            .lan(host: "127.0.0.1", port: port, scope: "local"),
            clientInfo: dialClientInfo
        )
        try await transport.send(Data([0x01, 0x02, 0x03]))
        let echoed = try await transport.receive()
        await transport.close()
        await server.stop()

        #expect(echoed == Data([0x01, 0x02, 0x03]))
        #expect(transport.transportKind == "lan")
    }

    @Test func lanConnectTimeoutToUnreachableIPFiresConnectTimeout() async {
        await expectDialError(.connectTimeout) {
            _ = try await DialClient.dial(
                .lan(host: "10.255.255.1", port: 65_534, scope: "local"),
                clientInfo: dialClientInfo,
                timeout: .milliseconds(200)
            )
        }
    }

    @Test func relayConnectTimeoutCancelsPendingOpen() async throws {
        let server = TCPHangingServer()
        try await server.start()
        let port = await server.port

        await expectDialError(.connectTimeout) {
            _ = try await DialClient.dial(
                .relay(
                    endpoint: try relayEndpoint(port: port),
                    instanceID: "instance-1",
                    deviceToken: "device-token"
                ),
                clientInfo: dialClientInfo,
                timeout: .milliseconds(200)
            )
        }
        await server.stop()
    }

    @Test func relayConnectsSendsReceivesAndCarriesAuthorizationHeader() async throws {
        let server = WebSocketEchoServer()
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dial(
            .relay(
                endpoint: try relayEndpoint(port: port),
                instanceID: "instance-1",
                deviceToken: "device-token"
            ),
            clientInfo: dialClientInfo
        )
        try await transport.send(Data([0x04, 0x05, 0x06]))
        let echoed = try await transport.receive()
        await transport.close()
        let authorization = await server.authorizationHeader
        let userAgent = await server.userAgentHeader
        await server.stop()

        #expect(echoed == Data([0x04, 0x05, 0x06]))
        #expect(authorization == "Bearer device-token")
        #expect(userAgent == dialClientInfo.userAgent)
        #expect(transport.transportKind == "relay")
    }

    @Test func pairRelayConnectsWithPairDialPathAndPairKeyHeader() async throws {
        let server = WebSocketEchoServer()
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dialPairRelay(
            endpoint: try relayEndpoint(port: port),
            pairKey: try PairWindowRelayKey(sBytes: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
            clientInfo: dialClientInfo
        )
        try await transport.send(Data([0x07, 0x08, 0x09]))
        let echoed = try await transport.receive()
        await transport.close()
        let authorization = await server.authorizationHeader
        let pairKey = await server.pairKeyHeader
        let userAgent = await server.userAgentHeader
        await server.stop()

        #expect(echoed == Data([0x07, 0x08, 0x09]))
        #expect(authorization == nil)
        #expect(pairKey == "e34481a4cde647ba9c9fb29a59e18271")
        #expect(userAgent == dialClientInfo.userAgent)
        #expect(transport.transportKind == "relay")
    }

    @Test func webSocketURLBuildsSessionAndPairDialPaths() throws {
        let relayURL = try RelayWSTransport.webSocketURL(
            endpoint: URL(string: "https://link.solstone.app")!,
            path: "session/dial",
            instanceID: "instance-123"
        )
        let pairURL = try RelayWSTransport.webSocketURL(
            endpoint: URL(string: "https://link.solstone.app/base")!,
            path: "session/pair-dial",
            instanceID: nil
        )

        #expect(relayURL.absoluteString == "wss://link.solstone.app/session/dial?instance=instance-123")
        #expect(pairURL.absoluteString == "wss://link.solstone.app/base/session/pair-dial")
    }

    @Test func relay401MapsUnauthorized() async throws {
        try await expectRelayStatus(401, .relayUnauthorized)
    }

    @Test func pairRelay401MapsPairingWindowClosed() async throws {
        // proto/session.md:239 and proto/pair-window.md:108 define the uniform pair-dial 401 surface.
        let server = WebSocketFailingServer(statusCode: 401)
        try await server.start()
        let port = await server.port

        await expectDialError(.pairingWindowClosed) {
            _ = try await DialClient.dialPairRelay(
                endpoint: try relayEndpoint(port: port),
                pairKey: try PairWindowRelayKey(sBytes: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
                clientInfo: dialClientInfo
            )
        }
        await server.stop()
    }

    @Test func relay403MapsUnauthorized() async throws {
        try await expectRelayStatus(403, .relayUnauthorized)
    }

    @Test func relay402MapsNotEntitled() async throws {
        try await expectRelayStatus(402, .relayNotEntitled)
    }

    @Test func relay404MapsInstanceUnknown() async throws {
        try await expectRelayStatus(404, .relayInstanceUnknown)
    }

    @Test func relay500MapsHandshakeFailed() async throws {
        try await expectRelayStatus(500, .wsHandshakeFailed(httpStatus: 500))
    }

    @Test func relayTextFrameMapsUnexpectedTextFrame() async throws {
        let server = WebSocketEchoServer(textOnConnect: "nope")
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dial(
            .relay(
                endpoint: try relayEndpoint(port: port),
                instanceID: "instance-1",
                deviceToken: "device-token"
            ),
            clientInfo: dialClientInfo
        )
        await expectDialError(.unexpectedTextFrame) {
            _ = try await transport.receive()
        }
        await transport.close()
        await server.stop()
    }

    @Test func relayClose4401MapsRelayCloseUnauthorizedOnReceive() async throws {
        // proto/tokens.md:260 maps WebSocket close code 4401 to unauthorized.
        let server = WebSocketClosingServer(closeCode: 4401)
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dial(
            .relay(
                endpoint: try relayEndpoint(port: port),
                instanceID: "instance-1",
                deviceToken: "device-token"
            ),
            clientInfo: dialClientInfo
        )
        await expectDialError(.relayCloseUnauthorized) {
            _ = try await transport.receive()
        }
        await transport.close()
        await server.stop()
    }

    @Test func relayClose4401MapsRelayCloseUnauthorizedOnSendAfterCloseRecorded() async throws {
        // proto/tokens.md:260 maps WebSocket close code 4401 to unauthorized.
        let server = WebSocketClosingServer(closeCode: 4401)
        try await server.start()
        let port = await server.port

        let transport = try await DialClient.dial(
            .relay(
                endpoint: try relayEndpoint(port: port),
                instanceID: "instance-1",
                deviceToken: "device-token"
            ),
            clientInfo: dialClientInfo
        )
        await expectDialError(.relayCloseUnauthorized) {
            _ = try await transport.receive()
        }
        await expectDialError(.relayCloseUnauthorized) {
            try await transport.send(Data([0x01]))
        }
        await transport.close()
        await server.stop()
    }

    @Test func relayDialRequestUsesBearerInstanceAndUserAgent() throws {
        let request = try RelayWSTransport.makeRequest(
            endpoint: URL(string: "https://link.solstone.app")!,
            path: "session/dial",
            credential: .session(instanceID: "instance", authToken: "token"),
            clientInfo: SPLClientInfo(userAgent: "spl-client/42")
        )

        #expect(request.url?.absoluteString == "wss://link.solstone.app/session/dial?instance=instance")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token")
        #expect(request.value(forHTTPHeaderField: "Sec-Pair-Key") == nil)
        #expect(request.value(forHTTPHeaderField: "User-Agent") == "spl-client/42")
    }

    @Test func relayHTTP503FailsBeforeTransportOpen() async throws {
        let server = WebSocketFailingServer(statusCode: 503)
        try await server.start()
        let port = await server.port

        await expectDialError(.wsHandshakeFailed(httpStatus: 503)) {
            _ = try await DialClient.dial(
                .relay(endpoint: try relayEndpoint(port: port), instanceID: "instance", deviceToken: "token"),
                clientInfo: dialClientInfo,
                timeout: .seconds(2)
            )
        }
        await server.stop()
    }

    @Test func openFailurePathRoutesThroughCloseCodeMapper() async throws {
        let server = WebSocketFailingServer(statusCode: 503)
        try await server.start()
        let port = await server.port

        let thrown: DialError
        do {
            _ = try await DialClient.dial(
                .relay(endpoint: try relayEndpoint(port: port), instanceID: "instance", deviceToken: "token"),
                clientInfo: dialClientInfo,
                timeout: .seconds(2)
            )
            await server.stop()
            Issue.record("Expected open failure")
            return
        } catch let error as DialError {
            thrown = error
        } catch {
            await server.stop()
            Issue.record("Expected DialError, got \(error)")
            return
        }
        await server.stop()

        let mapped = RelayWSTransport.openFailureError(thrown, taskCloseCode: 0, recordedCloseCode: nil)
        #expect((mapped as? DialError) == thrown)
        #expect(thrown == .wsHandshakeFailed(httpStatus: 503))
    }

    @Test func relayCloseReasonMapsKnownCodes() {
        #expect(RelayWSTransport.relayCloseReason(forCloseCode: 4401) == .relayCloseUnauthorized)
        #expect(RelayWSTransport.relayCloseReason(forCloseCode: 1000) == nil)
        #expect(RelayWSTransport.relayCloseReason(forCloseCode: 1001) == nil)
        #expect(RelayWSTransport.relayCloseReason(forCloseCode: 4999) == nil)
    }

    @Test func relayClose4401MapsRelayCloseUnauthorizedOnOpenFailure() async throws {
        // proto/tokens.md:260 maps WebSocket close code 4401 to unauthorized.
        // URLSession reports didOpenWithProtocol after a valid 101 even when that same server write includes a
        // 4401 close frame; the close is therefore observable on receive/send, not as an open failure.
        let taskClose = RelayWSTransport.openFailureError(
            DialError.connectionFailed("open failed"),
            taskCloseCode: 4401,
            recordedCloseCode: nil
        )
        let recordedClose = RelayWSTransport.openFailureError(
            DialError.connectionFailed("open failed"),
            taskCloseCode: 0,
            recordedCloseCode: 4401
        )

        #expect((taskClose as? DialError) == .relayCloseUnauthorized)
        #expect((recordedClose as? DialError) == .relayCloseUnauthorized)
    }

    @Test func dialErrorDoesNotReferencePairError() throws {
        let source = try Self.sourceText("Sources/SPLTunnel/Dial/DialClient.swift")
        #expect(!source.contains("PairError"))
        #expect(!source.contains("Bundle.main"))
    }

    private func expectRelayStatus(_ status: Int, _ expected: DialError) async throws {
        let server = WebSocketFailingServer(statusCode: status)
        try await server.start()
        let port = await server.port

        await expectDialError(expected) {
            _ = try await DialClient.dial(
                .relay(
                    endpoint: try relayEndpoint(port: port),
                    instanceID: "instance-1",
                    deviceToken: "device-token"
                ),
                clientInfo: dialClientInfo
            )
        }
        await server.stop()
    }

    private func relayEndpoint(port: Int) throws -> URL {
        try #require(URL(string: "ws://127.0.0.1:\(port)"))
    }

    private func expectDialError(
        _ expected: DialError,
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected \(expected)")
        } catch let error as DialError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }

    private static func sourceText(_ relativePath: String) throws -> String {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = directory.appendingPathComponent(relativePath)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try String(contentsOf: candidate, encoding: .utf8)
            }
            directory.deleteLastPathComponent()
        }
        let cwdCandidate = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(relativePath)
        return try String(contentsOf: cwdCandidate, encoding: .utf8)
    }
}
