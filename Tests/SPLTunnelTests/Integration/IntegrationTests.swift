// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Darwin.Mach
import Foundation
import Network
import Security
import Testing
@testable import SPLTunnel

private let integrationClientInfo = SPLClientInfo(userAgent: "spl-swift-integration-tests/1")

@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["SPL_INTEGRATION"] == "1"))
struct IntegrationTests {
    @Test func directPairConnectsAndRoundTripsHTTP() async throws {
        try await Self.withConnectedHome(pairingMode: .direct) { home in
            try await Self.expectStatusRoundTrip(proxyPort: home.proxyPort)
            try await Self.expectEchoRoundTrip(proxyPort: home.proxyPort, message: "direct-ok")
        }
    }

    @Test func relayPairConnectsAndRoundTripsHTTP() async throws {
        try await Self.withConnectedHome(pairingMode: .relay) { home in
            try await Self.expectStatusRoundTrip(proxyPort: home.proxyPort)
            try await Self.expectEchoRoundTrip(proxyPort: home.proxyPort, message: "relay-ok")
            #expect(await home.relay.pairKeyHeader == "e34481a4cde647ba9c9fb29a59e18271")
        }
    }

    @Test func tenMiBUploadIsByteEqualAndReceiveQueueBounded() async throws {
        try await Self.withConnectedHome(pairingMode: .direct) { home in
            let payload = Self.deterministicData(count: 10 * 1_024 * 1_024, seed: 0x5a)
            let allowedSlack = Int(MuxConstants.recommendedChunk)
            let allowedPeak = Int(MuxConstants.initialCredit) + allowedSlack
            var observations: [UploadObservation] = []

            for run in 1...5 {
                let observation = try await Self.performUpload(
                    payload: payload,
                    proxyPort: home.proxyPort,
                    home: home.home
                )
                observations.append(observation)
                #expect(observation.receiveQueuePeak <= allowedPeak)
                Self.recordMetric(
                    "tenMiBUpload run=\(run) mux_receive_peak=\(observation.receiveQueuePeak) " +
                    "initial_credit=\(MuxConstants.initialCredit) slack=\(allowedSlack) " +
                    "rss_growth=\(observation.rssGrowthDescription) " +
                    "app_buffer_peak=\(observation.appBufferPeak)"
                )
            }

            #expect(observations.count == 5)
        }
    }

    @Test func threeConcurrentUploadsCompleteIndependently() async throws {
        try await Self.withConnectedHome(pairingMode: .direct) { home in
            let sizes = [1_024 * 1_024, 2 * 1_024 * 1_024, 3 * 1_024 * 1_024]
            let proxyPort = home.proxyPort
            let mockHome = home.home

            try await withThrowingTaskGroup(of: Void.self) { group in
                for (index, size) in sizes.enumerated() {
                    group.addTask {
                        let payload = Self.deterministicData(count: size, seed: UInt8(0x20 + index))
                        _ = try await Self.performUpload(payload: payload, proxyPort: proxyPort, home: mockHome)
                    }
                }
                try await group.waitForAll()
            }
        }
    }

    @Test func reconnectRetainsLoopbackPortAcrossRestarts() async throws {
        let connected = try await Self.makePairedHome(
            pairingMode: .direct,
            homePort: FixedPortReclaimTestPorts.integrationMockHomeRebindPort
        )
        let supervisor = TunnelSupervisor(
            pairing: connected.pairing,
            clientInfo: integrationClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            sleeper: { _ in }
        )
        let states = await stateProbe(for: supervisor)
        let proxy = LoopbackProxy(opener: supervisor)
        let loopbackPort = try await proxy.start()
        var completedCycles = 0

        do {
            _ = try await supervisor.connect(endpoints: [connected.endpoint])
            try await Self.expectDirectStateSequence(states: states, endpoint: connected.endpoint)
            Self.recordMetric("stablePort initial_connected loopback_port=\(loopbackPort)")
            try await Self.expectStatusRoundTrip(proxyPort: loopbackPort)

            let connectedVia = connected.endpoint.connectedVia
            var expectedConnectedCount = await states.count(.connected(via: connectedVia))
            let fixedHomePort = connected.endpoint.portForTest

            for _ in 1...3 {
                Self.recordMetric("stablePort cycle=\(completedCycles + 1) stopping_home")
                await connected.home.stop()
                #expect(await waitUntil("healable reconnect status", timeout: .seconds(3)) {
                    guard let status = await supervisor.reconnectStatus else {
                        return false
                    }
                    return status.reason != nil && status.terminalPause == false
                })

                _ = try await connected.home.start(port: fixedHomePort)
                Self.recordMetric("stablePort cycle=\(completedCycles + 1) restarted_home")
                expectedConnectedCount += 1
                let targetConnectedCount = expectedConnectedCount
                #expect(await waitUntil("reconnected MockHome", timeout: .seconds(5)) {
                    await states.count(.connected(via: connectedVia)) >= targetConnectedCount
                })
                #expect(await waitUntil("reconnect status cleared", timeout: .seconds(2)) {
                    await supervisor.reconnectStatus == nil
                })
                #expect(await states.count(.tlsHandshaking(via: connectedVia)) >= targetConnectedCount)
                #expect(try await proxy.start() == loopbackPort)
                try await Self.expectStatusRoundTrip(proxyPort: loopbackPort)
                completedCycles += 1
            }

            Self.recordMetric("stablePort cycles=\(completedCycles) loopback_port=\(loopbackPort)")
            await proxy.stop()
            await supervisor.disconnect()
            await states.stop()
            await connected.stop()
        } catch {
            await proxy.stop()
            await supervisor.disconnect()
            await states.stop()
            await connected.stop()
            throw error
        }
    }

    private static func withConnectedHome<T: Sendable>(
        pairingMode: PairingMode,
        operation: (ConnectedHome) async throws -> T
    ) async throws -> T {
        let paired = try await makePairedHome(pairingMode: pairingMode)
        let session = TunnelSession(
            pairing: paired.pairing,
            clientInfo: integrationClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: false)
        )
        let states = await stateProbe(for: session)
        let proxy = LoopbackProxy(opener: session)

        do {
            _ = try await session.connect(endpoints: [paired.endpoint])
            try await expectDirectStateSequence(states: states, endpoint: paired.endpoint)
            let proxyPort = try await proxy.start()
            let connected = ConnectedHome(
                home: paired.home,
                relay: paired.relay,
                session: session,
                proxy: proxy,
                proxyPort: proxyPort,
                endpoint: paired.endpoint
            )
            let result = try await operation(connected)
            await proxy.stop()
            await session.disconnect()
            await states.stop()
            await paired.stop()
            return result
        } catch {
            await proxy.stop()
            await session.disconnect()
            await states.stop()
            await paired.stop()
            throw error
        }
    }

    private static func makePairedHome(
        pairingMode: PairingMode,
        homePort: Int? = nil
    ) async throws -> PairedHome {
        let bundle = try TestCA.make()
        let authorizedClients = MockAuthorizedClients()
        let home = MockHome(bundle: bundle, authorizedClients: authorizedClients)
        let homeEndpoint = try await home.start(port: homePort)
        let relay = try MockRelay()
        let relayEndpoint = try await relay.start()
        let tokenBytes = pairingMode.tokenBytes
        let pairingServer = PairingMuxServer(
            bundle: bundle,
            directPair: PairingDirectPairConfiguration(
                token: CertChain.hex(tokenBytes),
                instanceID: try pairingMode.instanceID(bundle: bundle),
                homeLabel: "test home",
                homeAttestation: "test-attestation",
                localEndpoints: [
                    LocalEndpoint(host: "127.0.0.1", port: Int(homeEndpoint.port), scope: "loopback"),
                ],
                authorizedClients: authorizedClients
            )
        )

        do {
            try await pairingServer.start()
            let pairingServerPort = await pairingServer.port
            let pairURL: PairURL
            switch pairingMode {
            case .direct:
                pairURL = try directPairURL(port: pairingServerPort, nonce: tokenBytes, bundle: bundle)
            case .relay:
                try await relay.routePairDial(toTLSPort: pairingServerPort)
                pairURL = try relayPairURL(sBytes: tokenBytes, bundle: bundle)
            }

            let pairing = try await PairClient(clientInfo: integrationClientInfo).pair(
                pairURL: pairURL,
                deviceLabel: "Test Device",
                relayEndpoint: RelayEndpoint.unchecked(relayEndpoint)
            )
            await pairingServer.stop()
            return PairedHome(
                home: home,
                relay: relay,
                pairing: pairing,
                endpoint: .lan(host: "127.0.0.1", port: Int(homeEndpoint.port), scope: "loopback")
            )
        } catch {
            await pairingServer.stop()
            await home.stop()
            await relay.stop()
            throw error
        }
    }

    private static func expectDirectStateSequence(states: StateProbe, endpoint: TransportEndpoint) async throws {
        let via = endpoint.connectedVia
        #expect(await waitUntil("connecting via direct endpoint", timeout: .seconds(2)) {
            await states.contains(.connecting(candidates: [via]))
        })
        #expect(await waitUntil("tls handshaking via direct endpoint", timeout: .seconds(2)) {
            await states.contains(.tlsHandshaking(via: via))
        })
        #expect(await waitUntil("connected via direct endpoint", timeout: .seconds(2)) {
            await states.contains(.connected(via: via))
        })
    }

    private static func expectStatusRoundTrip(proxyPort: UInt16) async throws {
        let response = try await sendRawHTTPRequest(
            path: "/app/network/api/status",
            proxyPort: proxyPort
        )
        #expect(response.statusCode == 200)
        let json = try jsonObject(response.body)
        #expect(json["status"] as? String == "ok")
        #expect(json["echo"] as? String == "mock-home")
    }

    private static func expectEchoRoundTrip(proxyPort: UInt16, message: String) async throws {
        var components = URLComponents(string: "http://127.0.0.1:\(proxyPort)/echo")!
        components.queryItems = [URLQueryItem(name: "msg", value: message)]
        let response = try await sendRawHTTPRequest(
            path: "/echo?" + (components.percentEncodedQuery ?? ""),
            proxyPort: proxyPort
        )
        #expect(response.statusCode == 200)
        let json = try jsonObject(response.body)
        #expect(json["msg"] as? String == message)
    }

    @discardableResult
    private static func performUpload(payload: Data, proxyPort: UInt16, home: MockHome) async throws -> UploadObservation {
        await home.resetReceiveQueueHighWaterMark()
        await home.resetAppRequestBufferHighWaterMark()
        let request = makeMultipartUploadRequest(payload: payload)
        let beforeRSS = residentSetSize()
        let response = try await sendRawHTTPRequest(request, proxyPort: proxyPort)
        let afterRSS = residentSetSize()
        #expect(response.statusCode == 200)
        let json = try jsonObject(response.body)
        #expect(json["received_bytes"] as? Int == payload.count)
        #expect(firstFileSHA256(in: json) == sha256Hex(payload))

        return UploadObservation(
            receiveQueuePeak: await home.receiveQueueHighWaterMark(),
            appBufferPeak: await home.appRequestBufferHighWaterMark(),
            rssBefore: beforeRSS,
            rssAfter: afterRSS
        )
    }

    private static func directPairURL(port: Int, nonce: [UInt8], bundle: TestCA.Bundle) throws -> PairURL {
        var bytes: [UInt8] = [
            0x05,
            0x01,
            0x01,
            UInt8((port >> 8) & 0xff),
            UInt8(port & 0xff),
            127,
            0,
            0,
            1,
        ]
        bytes.append(contentsOf: nonce)
        bytes.append(contentsOf: try caCertificatePrefix(bundle: bundle))
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }

    private static func relayPairURL(sBytes: [UInt8], bundle: TestCA.Bundle) throws -> PairURL {
        let caSPKI = try caSPKI(bundle: bundle)
        let caPrefix = Array(SHA256.hash(data: Data(caSPKI)).prefix(16))
        let bytes: [UInt8] = [0x06] + sBytes + [0x01] + caPrefix + [0x00]
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }

    private static func caCertificatePrefix(bundle: TestCA.Bundle) throws -> [UInt8] {
        let certificate = try #require(try CertChain.certificates(fromPEM: bundle.caCertificatePEM).first)
        let der = SecCertificateCopyData(certificate) as Data
        return Array(SHA256.hash(data: der).prefix(16))
    }

    private static func caSPKI(bundle: TestCA.Bundle) throws -> [UInt8] {
        let certificate = try #require(try CertChain.certificates(fromPEM: bundle.caCertificatePEM).first)
        return try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: certificate)
    }

    fileprivate static func caJID(bundle: TestCA.Bundle) throws -> String {
        try CertChain.jidFromSPKI(caSPKI(bundle: bundle))
    }

    private static func jsonObject(_ data: Data) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private static func makeMultipartUploadRequest(payload: Data) -> Data {
        let boundary = "spl-swift-integration-boundary"

        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"upload.bin\"\r\n".utf8))
        body.append(Data("Content-Type: application/octet-stream\r\n\r\n".utf8))
        body.append(payload)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))
        let head = [
            "POST /app/observer/ingest HTTP/1.1",
            "Host: 127.0.0.1",
            "Content-Type: multipart/form-data; boundary=\(boundary)",
            "Content-Length: \(body.count)",
            "Connection: close",
            "",
            "",
        ].joined(separator: "\r\n")

        var request = Data(head.utf8)
        request.append(body)
        return request
    }

    private static func sendRawHTTPRequest(path: String, proxyPort: UInt16) async throws -> HTTPResponse {
        let request = Data([
            "GET \(path) HTTP/1.1",
            "Host: 127.0.0.1",
            "Connection: close",
            "",
            "",
        ].joined(separator: "\r\n").utf8)
        return try await sendRawHTTPRequest(request, proxyPort: proxyPort)
    }

    private static func sendRawHTTPRequest(_ request: Data, proxyPort: UInt16) async throws -> HTTPResponse {
        let endpointPort = try #require(NWEndpoint.Port(rawValue: proxyPort))
        let connection = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        let ready = startAndReturnReadyWaiter(connection)
        try await ready.wait()
        defer {
            connection.cancel()
        }

        try await sendFinal(request, to: connection)
        return try parseHTTPResponse(try await collectRawResponse(from: connection))
    }

    private static func sendFinal(_ data: Data, to connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: data,
                    contentContext: .finalMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume()
                        }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func collectRawResponse(from connection: NWConnection) async throws -> Data {
        var response = Data()
        while true {
            let chunk: Data?
            let isComplete: Bool
            do {
                (chunk, isComplete) = try await LoopbackProxy.receive(from: connection)
            } catch {
                if !response.isEmpty {
                    return response
                }
                throw error
            }
            if let chunk {
                response.append(chunk)
            }
            if isComplete || chunk == nil {
                return response
            }
        }
    }

    private static func parseHTTPResponse(_ data: Data) throws -> HTTPResponse {
        let separator = Data("\r\n\r\n".utf8)
        let range = try #require(data.range(of: separator))
        let headerText = try #require(String(data: data[..<range.lowerBound], encoding: .utf8))
        let statusLine = try #require(headerText.components(separatedBy: "\r\n").first)
        let parts = statusLine.split(separator: " ")
        let statusText = try #require(parts.dropFirst().first)
        let statusCode = try #require(Int(statusText))
        return HTTPResponse(statusCode: statusCode, body: Data(data[range.upperBound...]))
    }

    private static func firstFileSHA256(in json: [String: Any]) -> String? {
        let files = json["files"] as? [[String: Any]]
        return files?.first?["sha256"] as? String
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func deterministicData(count: Int, seed: UInt8) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { buffer in
            let bytes = buffer.bindMemory(to: UInt8.self)
            for index in bytes.indices {
                bytes[index] = UInt8((index * 31 + Int(seed)) & 0xff)
            }
        }
        return data
    }

    private static func residentSetSize() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<natural_t>.stride)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else {
            return nil
        }
        return UInt64(info.phys_footprint)
    }

    private static func recordMetric(_ message: String) {
        FileHandle.standardError.write(Data("[integration] \(message)\n".utf8))
    }
}

private enum PairingMode {
    case direct
    case relay

    var tokenBytes: [UInt8] {
        switch self {
        case .direct:
            Array(UInt8(0x10)...UInt8(0x1f))
        case .relay:
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        }
    }

    func instanceID(bundle: TestCA.Bundle) throws -> String {
        switch self {
        case .direct:
            "test-instance"
        case .relay:
            try IntegrationTests.caJID(bundle: bundle)
        }
    }
}

private struct PairedHome: Sendable {
    let home: MockHome
    let relay: MockRelay
    let pairing: StoredPairing
    let endpoint: TransportEndpoint

    func stop() async {
        await home.stop()
        await relay.stop()
    }
}

private struct ConnectedHome: Sendable {
    let home: MockHome
    let relay: MockRelay
    let session: TunnelSession
    let proxy: LoopbackProxy
    let proxyPort: UInt16
    let endpoint: TransportEndpoint
}

private struct UploadObservation: Sendable {
    let receiveQueuePeak: Int
    let appBufferPeak: Int
    let rssBefore: UInt64?
    let rssAfter: UInt64?

    var rssGrowthDescription: String {
        guard let rssBefore, let rssAfter else {
            return "unavailable"
        }
        let growth = rssAfter > rssBefore ? rssAfter - rssBefore : 0
        return "\(growth)"
    }
}

private struct HTTPResponse: Sendable {
    let statusCode: Int
    let body: Data
}

private extension TransportEndpoint {
    var portForTest: Int {
        if case .lan(_, let port, _, _) = self {
            return port
        }
        return 0
    }
}
