// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Testing
@testable import SPLTunnel

private let pairClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")
private let pairClientRelayHost = "pairclient-relay.test"

@Suite("PairClient Direct", .serialized)
struct PairClientDirectTests {
    @Test func candidateExhaustionOrderRemembersCAFingerprintMismatch() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
            PairCandidate(address: "192.168.0.30", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(FakeLANPairError.unreachable),
            .error(InnerTLSError.caFingerprintMismatch),
            .error(FakeLANPairError.unreachable),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanCandidatesExhausted(sawCAFingerprintMismatch: true)) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint,
                orderCandidates: { Array($0.reversed()) }
            )
        }

        let requests = await transport.requests
        #expect(requests.map(\.host) == ["192.168.0.30", "192.168.0.20", "192.168.0.10"])
    }

    @Test func singleCandidateExhaustionRethrowsRawError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(InnerTLSError.caFingerprintMismatch),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanCAFingerprintMismatch) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }
    }

    @Test func nonceExpiredShortCircuitsCandidateLoop() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 410, body: Data()),
            .error(FakeLANPairError.unreachable),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.nonceExpired) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.requestCount == 1)
    }

    @Test func pairingWindowClosedShortCircuitsCandidateLoop() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CertlessPairError.closedBeforeStatus),
            .error(FakeLANPairError.unreachable),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.pairingWindowClosed) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.requestCount == 1)
    }

    @Test func directRequestLineUsesQueryTokenAndBodyOmitsNonce() async throws {
        // proto/pairing.md:105-115 documents the CSR post; journal interop accepts the nonce in the mux request query.
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let responseBody = try Self.pairResponseData(bundle: fixture)
        let nonce = Array(UInt8(0x00)...UInt8(0x0f))
        let pairURL = try Self.directPairURL(
            candidates: [PairCandidate(address: "192.168.0.10", port: 7657)],
            nonce: nonce
        )
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: responseBody),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        let request = try #require(await transport.requests.first)
        let parsed = try Self.parseRequest(request.requestBytes)
        let json = try #require(JSONSerialization.jsonObject(with: parsed.body) as? [String: String])
        #expect(parsed.requestLine == "POST /app/network/pair?token=000102030405060708090a0b0c0d0e0f HTTP/1.1")
        #expect(json["csr"] != nil)
        #expect(json["device_label"] == "test phone")
        #expect(json["nonce"] == nil)
    }

    @Test func dialedEndpointPromotionPreservesScopeAndDedupes() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let dialed = LocalEndpoint(host: "192.168.0.10", port: 7657, scope: "wifi")
        let other = LocalEndpoint(host: "192.168.0.20", port: 7657, scope: "ethernet")
        let responseBody = try Self.pairResponseData(bundle: fixture, localEndpoints: [other, dialed])
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: responseBody),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        let pairing = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(pairing.localEndpoints == [dialed, other])
    }

    @Test func enrollmentFailureReturnsUnavailableOnValidPairing() async throws {
        // proto/pairing.md:147-179 cert storage precedes relay enrollment, so enrollment failure preserves LAN pairing.
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let responseBody = try Self.pairResponseData(bundle: fixture)
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: responseBody),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        let pairing = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(pairing.relayEnrollment == .unavailable)
        #expect(HTTPStubProtocol.state.requests(forHost: pairClientRelayHost).count == 1)
    }

    fileprivate static func directPairURL(
        candidates: [PairCandidate],
        nonce: [UInt8] = Array(UInt8(0x10)...UInt8(0x1f)),
        caFingerprintBytes: [UInt8] = Array(UInt8(0xa0)...UInt8(0xaf))
    ) throws -> PairURL {
        let first = try #require(candidates.first)
        var bytes: [UInt8] = [
            0x05,
            0x01,
            UInt8(candidates.count),
            UInt8(first.port >> 8),
            UInt8(first.port & 0xff),
        ]
        for candidate in candidates {
            bytes.append(contentsOf: candidate.address.split(separator: ".").map { UInt8($0)! })
        }
        bytes.append(contentsOf: nonce)
        bytes.append(contentsOf: caFingerprintBytes)
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }

    fileprivate static func relayFailureSession(status: Int) -> URLSession {
        makeHTTPStubSession(host: pairClientRelayHost) { _ in
            .http(status: status, data: Data())
        }
    }

    private static var relayEndpoint: URL {
        URL(string: "https://\(pairClientRelayHost)")!
    }

    fileprivate static func pairResponseData(
        bundle: TestCA.Bundle,
        instanceID: String = "instance-1",
        caChain: [String]? = nil,
        localEndpoints: [LocalEndpoint] = []
    ) throws -> Data {
        let endpoints = localEndpoints.map {
            [
                "ip": $0.host,
                "port": $0.port,
                "scope": $0.scope,
            ] as [String: Any]
        }
        return try JSONSerialization.data(withJSONObject: [
            "instance_id": instanceID,
            "home_label": "test home",
            "client_cert": bundle.clientCertificatePEM,
            "ca_chain": caChain ?? [bundle.caCertificatePEM],
            "home_attestation": "attestation",
            "local_endpoints": endpoints,
        ] as [String: Any])
    }

    private static func parseRequest(_ data: Data) throws -> (requestLine: String, body: Data) {
        let marker = Data("\r\n\r\n".utf8)
        let range = try #require(data.range(of: marker))
        let head = try #require(String(data: data[..<range.lowerBound], encoding: .utf8))
        let requestLine = try #require(head.components(separatedBy: "\r\n").first)
        return (requestLine, Data(data[range.upperBound...]))
    }
}

@Suite(
    "PairClient Relay",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct PairClientRelayTests {
    @Test func liveAnchorSPKIMismatchThrowsBeforeEnrollment() async throws {
        // proto/pair-window.md:98-104 binds the relay inner channel to the pinned CA; this fixture would pass if only the chain equality check were removed.
        defer { HTTPStubProtocol.state.reset(host: "127.0.0.1") }
        let live = try TestCA.make()
        let response = try TestCA.make()
        let pairURL = try Self.relayPairURL(bundle: live)
        let responseBody = try PairClientDirectTests.pairResponseData(
            bundle: live,
            instanceID: Self.caJID(bundle: live),
            caChain: [response.caCertificatePEM]
        )
        let client = PairClient(
            session: makeHTTPStubSession(host: "127.0.0.1") { _ in
                Issue.record("enrollment must not be attempted")
                return .http(status: 200, data: Data(#"{"device_token":"token"}"#.utf8))
            },
            clientInfo: pairClientInfo
        )

        try await Self.withRelayPairingServer(bundle: live, responseBody: responseBody) { relayEndpoint in
            await expectPairError(.relayInstanceMismatch) {
                _ = try await client.pair(
                    pairURL: pairURL,
                    deviceLabel: "test phone",
                    relayEndpoint: relayEndpoint
                )
            }
        }

        #expect(HTTPStubProtocol.state.requests(forHost: "127.0.0.1").isEmpty)
    }

    @Test func liveAnchorJIDMismatchThrowsBeforeEnrollment() async throws {
        // proto/pair-window.md:98-104 requires instance_id == jid(pinned CA); this fixture would pass if only the jid check were removed.
        defer { HTTPStubProtocol.state.reset(host: "127.0.0.1") }
        let live = try TestCA.make()
        let other = try TestCA.make()
        let pairURL = try Self.relayPairURL(bundle: live)
        let responseBody = try PairClientDirectTests.pairResponseData(
            bundle: live,
            instanceID: Self.caJID(bundle: other),
            caChain: [live.caCertificatePEM]
        )
        let client = PairClient(
            session: makeHTTPStubSession(host: "127.0.0.1") { _ in
                Issue.record("enrollment must not be attempted")
                return .http(status: 200, data: Data(#"{"device_token":"token"}"#.utf8))
            },
            clientInfo: pairClientInfo
        )

        try await Self.withRelayPairingServer(bundle: live, responseBody: responseBody) { relayEndpoint in
            await expectPairError(.relayInstanceMismatch) {
                _ = try await client.pair(
                    pairURL: pairURL,
                    deviceLabel: "test phone",
                    relayEndpoint: relayEndpoint
                )
            }
        }

        #expect(HTTPStubProtocol.state.requests(forHost: "127.0.0.1").isEmpty)
    }

    private static func withRelayPairingServer<T>(
        bundle: TestCA.Bundle,
        responseBody: Data,
        operation: (URL) async throws -> T
    ) async throws -> T {
        let pairingServer = PairingMuxServer(
            bundle: bundle,
            response: PairingHTTPServerResponse(status: 200, body: responseBody)
        )
        try await pairingServer.start()
        let relay = RelayBridgeServer(tlsPort: await pairingServer.port)
        try await relay.start()
        let relayEndpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))

        do {
            let result = try await operation(relayEndpoint)
            await relay.stop()
            await pairingServer.stop()
            return result
        } catch {
            await relay.stop()
            await pairingServer.stop()
            throw error
        }
    }

    private static func relayPairURL(bundle: TestCA.Bundle) throws -> PairURL {
        let sBytes: [UInt8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        let caSPKI = try caSPKI(bundle: bundle)
        let caPrefix = Array(SHA256.hash(data: Data(caSPKI)).prefix(16))
        let bytes: [UInt8] = [0x06] + sBytes + [0x01] + caPrefix + [0x00]
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }

    private static func caJID(bundle: TestCA.Bundle) throws -> String {
        try CertChain.jidFromSPKI(caSPKI(bundle: bundle))
    }

    private static func caSPKI(bundle: TestCA.Bundle) throws -> [UInt8] {
        let certificate = try #require(try CertChain.certificates(fromPEM: bundle.caCertificatePEM).first)
        return try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: certificate)
    }
}

private func expectPairError(
    _ expected: PairError,
    _ operation: @escaping @Sendable () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected)")
    } catch let error as PairError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), got \(error)")
    }
}
