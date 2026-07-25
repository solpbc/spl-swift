// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let pairingConformanceClientInfo = SPLClientInfo(userAgent: "spl-swift-conformance-tests/1")
private let pairingConformanceRelayHost = "pairing-conformance-relay.test"

@Suite("PairingConformance", .serialized)
struct PairingConformanceTests {
    @Test func directPairRejectsNonLocalIPv4CandidateBeforeDial() async throws {
        // proto/pairing.md:117 direct candidates outside the explicit allow-list are refused before dial.
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.0.2.10", port: 7657),
            PairCandidate(address: "192.0.2.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [])
        let client = Self.client(transport: transport)

        await Self.expectDirectAddressNotLocal {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.requests.isEmpty)
    }

    @Test func directPairRejectsMixedLocalAndNonLocalCandidatesBeforeDial() async throws {
        // proto/pairing.md:117 the direct allow-list applies to the whole candidate set, not only the first candidate.
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.0.2.20", port: 7657),
            PairCandidate(address: "169.254.0.30", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [])
        let client = Self.client(transport: transport)

        await Self.expectDirectAddressNotLocal {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.requests.isEmpty)
    }

    @Test func directPairAcceptsAllLocalCandidatesAndDialsNormally() async throws {
        // proto/pairing.md:117 admits RFC1918, RFC 6598, IPv4 link-local, IPv4 loopback, and IPv6 ULA direct candidates.
        let fixture = try TestCA.make()
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "169.254.0.20", port: 7657),
            PairCandidate(address: "127.0.0.30", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
        ])
        let client = Self.client(transport: transport)

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(await transport.requests.map(\.host) == ["192.168.0.10"])
    }

    @Test func directPairCGNATOnlyV04BeginsOneRequestToEncodedEndpoint() async throws {
        // proto/pairing.md:117 admits RFC 6598 shared address space 100.64.0.0/10.
        // proto/pairing.md:96 allows at most one nonce-bearing request; :147-157 define the request shape.
        let fixture = try TestCA.make()
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "100.64.0.5", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
        ])
        let client = Self.client(transport: transport)

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(await transport.requests.map(\.host) == ["100.64.0.5"])
        #expect(await transport.requestCount == 1)
    }

    @Test func directPairRFC1918AndCGNATMultiAdmitsIntact() async throws {
        // proto/pairing.md:117 admits 0x05 sets only when all candidates satisfy the direct allow-list.
        // proto/pairing.md:96 allows at most one nonce-bearing request; :147-157 define the request shape.
        let fixture = try TestCA.make()
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "100.64.0.5", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
        ])
        let client = Self.client(transport: transport)

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
    }

    @Test func directPairCGNATWithPublicRefusesWholeSetBeforeMaterialPrepareOrWrite() async throws {
        // proto/pairing.md:117 refuses the whole 0x05 link unless all candidates satisfy the direct allow-list.
        // This is not independently red on pre-RFC6598 code because CGNAT was also refused there.
        // directPairCGNATOnlyV04BeginsOneRequestToEncodedEndpoint and
        // directPairRFC1918AndCGNATMultiAdmitsIntact are the red pre-fix admission controls.
        let cases = [
            [
                PairCandidate(address: "100.64.0.5", port: 7657),
                PairCandidate(address: "192.0.2.42", port: 7657),
            ],
            [
                PairCandidate(address: "192.0.2.42", port: 7657),
                PairCandidate(address: "100.64.0.5", port: 7657),
            ],
            [
                PairCandidate(address: "100.64.0.5", port: 7657),
                PairCandidate(address: "100.64.0.5", port: 7657),
                PairCandidate(address: "192.0.2.42", port: 7657),
            ],
            [
                PairCandidate(address: "192.0.2.42", port: 7657),
                PairCandidate(address: "100.64.0.5", port: 7657),
                PairCandidate(address: "100.64.0.5", port: 7657),
            ],
        ]

        for candidates in cases {
            let material = PairingMaterialSpy()
            let pairURL = try Self.directPairURL(candidates: candidates)
            let transport = FakeLANPairTransport(outcomes: [])
            let client = PairClient(
                session: makeHTTPStubSession(host: pairingConformanceRelayHost) { _ in
                    .http(status: 503, data: Data())
                },
                lanTransport: transport,
                clientInfo: pairingConformanceClientInfo,
                materialGenerator: material.generate
            )

            await Self.expectDirectAddressNotLocal {
                _ = try await client.pair(
                    pairURL: pairURL,
                    deviceLabel: "test phone",
                    relayEndpoint: Self.relayEndpoint
                )
            }

            #expect(material.generationCount == 0)
            #expect(await transport.prepares.isEmpty)
            #expect(await transport.requests.isEmpty)
        }
    }

    @Test func relayEnrollBodyContainsOnlyInstanceIDAndHomeAttestation() throws {
        // proto/pairing.md:27 and proto/pairing.md:169-175 keep the relay blind to pairing payload; enroll carries only instance_id and home_attestation.
        let fixture = try TestCA.make()
        let response = try PairClient.decodeLANResponse(data: Self.pairResponseData(bundle: fixture))
        let endpoint = try RelayEndpoint(Self.relayEndpoint)
        let request = try PairClient.makeRelayRequest(
            relayEndpoint: endpoint,
            response: response,
            userAgent: pairingConformanceClientInfo.userAgent
        )

        let body = try #require(request.httpBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(Set(json.keys) == ["instance_id", "home_attestation"])
        #expect(json["instance_id"] as? String == "instance-1")
        #expect(json["home_attestation"] as? String == "attestation")
    }

    @Test func lanPairResponseMissingLocalEndpointsDefaultsEmptyAndStillPairs() async throws {
        // proto/pairing.md:151-159 defines the step-7 response body without local_endpoints; omission is accepted as an empty response endpoint list.
        let fixture = try TestCA.make()
        let responseBody = try Self.pairResponseDataOmittingLocalEndpoints(bundle: fixture)
        let response = try PairClient.decodeLANResponse(data: responseBody)
        #expect(response.localEndpoints == [])

        let dialed = LocalEndpoint(host: "192.168.0.10", port: 7657, scope: "")
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: dialed.host, port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: responseBody),
        ])
        let client = Self.client(transport: transport)

        let pairing = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(pairing.instanceID == "instance-1")
        #expect(pairing.homeLabel == "test home")
        #expect(!pairing.clientCertPEM.isEmpty)
        #expect(!pairing.caChainPEM.isEmpty)
        #expect(pairing.localEndpoints == [dialed])
    }

    private static func client(transport: FakeLANPairTransport) -> PairClient {
        PairClient(
            session: makeHTTPStubSession(host: pairingConformanceRelayHost) { _ in
                .http(status: 503, data: Data())
            },
            lanTransport: transport,
            clientInfo: pairingConformanceClientInfo
        )
    }

    private static var relayEndpoint: URL {
        URL(string: "https://\(pairingConformanceRelayHost)")!
    }

    private static func directPairURL(candidates: [PairCandidate]) throws -> PairURL {
        let nonce = Array(UInt8(0x10)...UInt8(0x1f))
        let caFingerprintBytes = Array(UInt8(0xa0)...UInt8(0xaf))
        if candidates.count == 1 {
            let first = try #require(candidates.first)
            let address = try Self.addressBytes(first.address)
            var bytes: [UInt8] = [0x04, 0x01]
            bytes.append(contentsOf: address)
            bytes.append(UInt8(first.port >> 8))
            bytes.append(UInt8(first.port & 0xff))
            bytes.append(contentsOf: nonce)
            bytes.append(contentsOf: caFingerprintBytes)
            return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
        }

        let first = try #require(candidates.first)
        var bytes: [UInt8] = [
            0x05,
            0x01,
            UInt8(candidates.count),
            UInt8(first.port >> 8),
            UInt8(first.port & 0xff),
        ]
        for candidate in candidates {
            bytes.append(contentsOf: try Self.addressBytes(candidate.address))
        }
        bytes.append(contentsOf: nonce)
        bytes.append(contentsOf: caFingerprintBytes)
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
    }

    private static func addressBytes(_ address: String) throws -> [UInt8] {
        let octets = address.split(separator: ".").compactMap { UInt8(String($0)) }
        #expect(octets.count == 4)
        return octets
    }

    private static func pairResponseData(bundle: TestCA.Bundle) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "instance_id": "instance-1",
            "home_label": "test home",
            "client_cert": bundle.clientCertificatePEM,
            "ca_chain": [bundle.caCertificatePEM],
            "home_attestation": "attestation",
            "local_endpoints": [],
        ] as [String: Any])
    }

    private static func pairResponseDataOmittingLocalEndpoints(bundle: TestCA.Bundle) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "instance_id": "instance-1",
            "home_label": "test home",
            "client_cert": bundle.clientCertificatePEM,
            "ca_chain": [bundle.caCertificatePEM],
            "home_attestation": "attestation",
        ] as [String: Any])
    }

    private static func expectDirectAddressNotLocal(
        _ operation: @escaping @Sendable () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected directAddressNotLocal")
        } catch let error as PairError {
            #expect(error == .directAddressNotLocal)
        } catch {
            Issue.record("Expected directAddressNotLocal, got \(error)")
        }
    }
}
