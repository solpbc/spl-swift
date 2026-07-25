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
        let transport = FakeLANPairTransport(prepareOutcomes: [
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

        let prepares = await transport.prepares
        #expect(prepares.map(\.host) == ["192.168.0.30", "192.168.0.20", "192.168.0.10"])
        #expect(await transport.requests.isEmpty)
    }

    @Test func validPermutationControlsCandidateOrder() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
            PairCandidate(address: "192.168.0.30", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint,
            orderCandidates: { Array($0.reversed()) }
        )

        #expect(await transport.prepares.map(\.host) == ["192.168.0.30"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func invalidCandidateOrdersFallBackToCanonicalUniqueOrder() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let canonical = [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ]
        let cases: [[PairCandidate]] = [
            canonical + [PairCandidate(address: "192.168.0.30", port: 7657)],
            [canonical[1]],
            [canonical[1], canonical[1]],
            [canonical[1], PairCandidate(address: "192.168.0.30", port: 7657)],
        ]

        for requestedOrder in cases {
            let fixture = try TestCA.make()
            let transport = FakeLANPairTransport(outcomes: [
                .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
            ])
            let client = PairClient(
                session: Self.relayFailureSession(status: 503),
                lanTransport: transport,
                clientInfo: pairClientInfo
            )
            let pairURL = try Self.directPairURL(candidates: canonical)

            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint,
                orderCandidates: { _ in requestedOrder }
            )

            #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
            #expect(await transport.requestCount == 1)
            #expect(await transport.closeCount == 1)
        }
    }

    @Test func duplicateCandidatesCoalesceBeforeOrdering() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let first = PairCandidate(address: "192.168.0.10", port: 7657)
        let second = PairCandidate(address: "192.168.0.20", port: 7657)
        let pairURL = try Self.directPairURL(candidates: [first, first, second])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 200, body: try Self.pairResponseData(bundle: fixture)),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint,
            orderCandidates: { candidates in
                #expect(candidates == [first, second])
                return Array(candidates.reversed())
            }
        )

        #expect(await transport.prepares.map(\.host) == ["192.168.0.20"])
        #expect(await transport.requestCount == 1)
    }

    @Test func preRequestRetryReusesOneMaterialAndSerializedBody() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let material = PairingMaterialSpy()
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(prepareOutcomes: [
            .error(FakeLANPairError.unreachable),
            .attempt(.response(status: 200, body: try Self.pairResponseData(bundle: fixture))),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo,
            materialGenerator: material.generate
        )

        _ = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(material.generationCount == 1)
        #expect(material.generatedPrivateKeys == ["key-1"])
        #expect(await transport.prepares.map(\.host) == ["192.168.0.10", "192.168.0.20"])
        #expect(await transport.requestCount == 1)
        let request = try #require(await transport.requests.first)
        let parsed = try Self.parseRequest(request.requestBytes)
        let expectedBody = try PairClient.encodePairRequestBody(csrPEM: "csr-1", deviceLabel: "test phone")
        #expect(parsed.body == expectedBody)
        let json = try #require(JSONSerialization.jsonObject(with: parsed.body) as? [String: String])
        #expect(json["csr"] == "csr-1")
    }

    @Test func genericPreRequestFailurePreservesUnderlyingError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(prepareOutcomes: [
            .error(FakeLANPairError.unreachable),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        do {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
            Issue.record("Expected lanRequestFailed")
        } catch let error as PairError {
            guard case .lanRequestFailed(let underlying) = error else {
                Issue.record("Expected lanRequestFailed, got \(error)")
                return
            }
            guard let underlying else {
                Issue.record("Expected underlying error")
                return
            }
            #expect((underlying as? FakeLANPairError) == .unreachable)
        } catch {
            Issue.record("Expected PairError, got \(error)")
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requests.isEmpty)
    }

    @Test func immediateWriteThrowAfterRequestCommitIsTerminal() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(FakeLANPairError.unreachable),
            .response(status: 200, body: Data()),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanRequestFailed(underlying: nil)) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func genericCommittedSendFailurePreservesUnderlyingError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(FakeLANPairError.unreachable),
            .response(status: 200, body: Data()),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        do {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
            Issue.record("Expected lanRequestFailed")
        } catch let error as PairError {
            guard case .lanRequestFailed(let underlying) = error else {
                Issue.record("Expected lanRequestFailed, got \(error)")
                return
            }
            guard let underlying else {
                Issue.record("Expected underlying error")
                return
            }
            #expect((underlying as? FakeLANPairError) == .unreachable)
        } catch {
            Issue.record("Expected PairError, got \(error)")
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func caFingerprintMismatchAfterRequestCommitIsTerminalWithMappedError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(InnerTLSError.caFingerprintMismatch),
            .response(status: 200, body: Data()),
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

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func cancellationAfterRequestCommitPropagatesAndIsTerminal() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CancellationError()),
            .response(status: 200, body: Data()),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        do {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
            Issue.record("expected cancellation")
        } catch is CancellationError {
            // Cancellation must remain observable to the caller after the request commit.
        } catch {
            Issue.record("expected CancellationError, got \(error)")
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func singleCandidateExhaustionRethrowsRawError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(prepareOutcomes: [
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

    @Test func closedBeforeStatusAfterRequestIsTerminal() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let fixture = try TestCA.make()
        let responseBody = try Self.pairResponseData(bundle: fixture)
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CertlessPairError.closedBeforeStatus),
            .response(status: 200, body: responseBody),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanClosedBeforeResponse) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func singleCandidateClosedBeforeStatusRethrowsLANClosedBeforeResponse() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CertlessPairError.closedBeforeStatus),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        do {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
            Issue.record("Expected lanClosedBeforeResponse")
        } catch let error as PairError {
            #expect(error == .lanClosedBeforeResponse)
            #expect(error != .pairingWindowClosed)
        } catch {
            Issue.record("Expected lanClosedBeforeResponse, got \(error)")
        }

        #expect(await transport.requestCount == 1)
    }

    @Test func allCandidatesClosedBeforeStatusStopsAfterFirstCommittedRequest() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CertlessPairError.closedBeforeStatus),
            .error(CertlessPairError.closedBeforeStatus),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanClosedBeforeResponse) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func malformedCertlessPairResponseAfterRequestCommitIsTerminalWithMappedError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
            PairCandidate(address: "192.168.0.20", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .error(CertlessPairError.malformedResponse),
            .response(status: 200, body: Data()),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanResponseInvalid(status: nil)) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }

        #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
        #expect(await transport.requestCount == 1)
        #expect(await transport.closeCount == 1)
    }

    @Test func responseErrorAfterRequestCommitIsTerminalWithMappedError() async throws {
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let cases: [(status: Int, body: Data, expected: PairError)] = [
            (200, Data(), .lanResponseInvalid(status: 200)),
            (400, Data(), .lanResponseInvalid(status: 400)),
            (500, Data(), .lanRequestFailed(underlying: nil)),
        ]

        for testCase in cases {
            let pairURL = try Self.directPairURL(candidates: [
                PairCandidate(address: "192.168.0.10", port: 7657),
                PairCandidate(address: "192.168.0.20", port: 7657),
            ])
            let transport = FakeLANPairTransport(outcomes: [
                .response(status: testCase.status, body: testCase.body),
                .response(status: 200, body: Data()),
            ])
            let client = PairClient(
                session: Self.relayFailureSession(status: 503),
                lanTransport: transport,
                clientInfo: pairClientInfo
            )

            await expectPairError(testCase.expected) {
                _ = try await client.pair(
                    pairURL: pairURL,
                    deviceLabel: "test phone",
                    relayEndpoint: Self.relayEndpoint
                )
            }

            #expect(await transport.prepares.map(\.host) == ["192.168.0.10"])
            #expect(await transport.requestCount == 1)
            #expect(await transport.closeCount == 1)
        }
    }

    @Test func pairingWindowClosed403BodyMapsPairingWindowClosed() async throws {
        // solpbc/spl wsgi.py write_simple_response emits this text/plain cert-less gate body;
        // no repo-local proto clause pins the exact text.
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 403, body: Data("pairing window closed\n".utf8)),
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
    }

    @Test func pairingTunnelWrongPath403BodyMapsLANResponseInvalid() async throws {
        // solpbc/spl wsgi.py write_simple_response emits this text/plain cert-less gate body;
        // no repo-local proto clause pins the exact text.
        defer { HTTPStubProtocol.state.reset(host: pairClientRelayHost) }
        let pairURL = try Self.directPairURL(candidates: [
            PairCandidate(address: "192.168.0.10", port: 7657),
        ])
        let transport = FakeLANPairTransport(outcomes: [
            .response(status: 403, body: Data("pairing tunnel may only use /app/network/pair\n".utf8)),
        ])
        let client = PairClient(
            session: Self.relayFailureSession(status: 503),
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        await expectPairError(.lanResponseInvalid(status: 403)) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: Self.relayEndpoint
            )
        }
    }

    @Test func lanClosedBeforeResponseEqualityAndStatusCode() {
        #expect(PairError.lanClosedBeforeResponse == .lanClosedBeforeResponse)
        #expect(PairError.lanClosedBeforeResponse != .pairingWindowClosed)
        #expect(PairError.lanClosedBeforeResponse.statusCode == nil)
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
        #expect(await transport.requestCount == 1)
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

    @Test func enrollmentCancellationReturnsUnavailableOnValidPairing() async throws {
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
            session: makeHTTPStubSession(host: pairClientRelayHost) { _ in
                .failure(CancellationError())
            },
            lanTransport: transport,
            clientInfo: pairClientInfo
        )

        let pairing = try await client.pair(
            pairURL: pairURL,
            deviceLabel: "test phone",
            relayEndpoint: Self.relayEndpoint
        )

        #expect(pairing.relayEnrollment == .unavailable)
        #expect(await transport.requestCount == 1)
        #expect(HTTPStubProtocol.state.requests(forHost: pairClientRelayHost).count == 1)
    }

    @Test func controlURLRejectsPlaintextRelaySchemes() throws {
        for endpoint in [
            URL(string: "http://relay.example")!,
            URL(string: "ws://relay.example")!,
        ] {
            #expect(throws: PairError.relayResponseInvalid(status: nil)) {
                _ = try PairClient.controlURL(endpoint, path: "enroll/device")
            }
        }

        let https = try PairClient.controlURL(URL(string: "https://relay.example/base")!, path: "enroll/device")
        let wss = try PairClient.controlURL(URL(string: "wss://relay.example/base")!, path: "enroll/device")

        #expect(https.absoluteString == "https://relay.example/base/enroll/device")
        #expect(wss.absoluteString == "https://relay.example/base/enroll/device")
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

@Suite("PairClient Relay Dial Failures", .serialized)
struct PairClientRelayDialFailureTests {
    @Test func pairRelay401MapsPairingWindowClosedThroughPairClient() async throws {
        let pairURL = try Self.relayPairURL()
        let server = WebSocketFailingServer(statusCode: 401)
        try await server.start()
        let port = await server.port
        let client = PairClient(clientInfo: pairClientInfo)

        await expectPairError(.pairingWindowClosed) {
            _ = try await client.pair(
                pairURL: pairURL,
                deviceLabel: "test phone",
                relayEndpoint: RelayEndpoint.unchecked(try #require(URL(string: "ws://127.0.0.1:\(port)")))
            )
        }
        await server.stop()
    }

    private static func relayPairURL() throws -> PairURL {
        let sBytes: [UInt8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        let caPrefix = Array(UInt8(0xa0)...UInt8(0xaf))
        let bytes: [UInt8] = [0x06] + sBytes + [0x01] + caPrefix + [0x00]
        return try PairURL.parse(URL(string: "https://go.solstone.app/p#\(Crockford32TestEncoding.encode(bytes))")!)
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
                    relayEndpoint: RelayEndpoint.unchecked(relayEndpoint)
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
                    relayEndpoint: RelayEndpoint.unchecked(relayEndpoint)
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
