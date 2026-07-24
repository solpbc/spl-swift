// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Security
import Testing
@testable import SPLTunnel

@Suite(
    "CertlessPairExchange",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct CertlessPairExchangeTests {
    @Test func sendsPairPostOverCertlessTLSMux() async throws {
        // proto/pairing.md:105-115 governs the CSR/device-label post; current journal interop carries the nonce in this mux request query.
        let fixture = try TestCA.make()
        let body = Data(#"{"csr":"csr-pem","device_label":"test phone"}"#.utf8)
        let request = CertlessPairExchange.encodeRequest(
            host: "127.0.0.1",
            path: "/app/network/pair?token=0123456789abcdef0123456789abcdef",
            jsonBody: body
        )
        let server = PairingMuxServer(
            bundle: fixture,
            response: PairingHTTPServerResponse(status: 200, body: Data(#"{"ok":true}"#.utf8))
        )
        try await server.start()
        let port = await server.port

        let exchange = CertlessPairExchange()
        let response = try await exchange.send(
            host: "127.0.0.1",
            port: port,
            caFingerprintBytes: try Self.caCertificateFingerprintPrefix(bundle: fixture),
            requestBytes: request
        )
        let observed = try #require(await server.lastRequest)
        await server.stop()

        #expect(response.status == 200)
        #expect(response.body == Data(#"{"ok":true}"#.utf8))
        #expect(observed.method == "POST")
        #expect(observed.path == "/app/network/pair?token=0123456789abcdef0123456789abcdef")
        let json = try #require(JSONSerialization.jsonObject(with: observed.body) as? [String: String])
        #expect(json["csr"] == "csr-pem")
        #expect(json["device_label"] == "test phone")
        #expect(json["nonce"] == nil)
    }

    @Test func rejectsChunkedAndRequiresContentLength() throws {
        let chunked = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".utf8)
        let missingLength = Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".utf8)

        expectCertlessPairError(.malformedResponse) {
            _ = try CertlessPairExchange.parseResponse(chunked)
        }
        expectCertlessPairError(.malformedResponse) {
            _ = try CertlessPairExchange.parseResponse(missingLength)
        }
    }

    private static func caCertificateFingerprintPrefix(bundle: TestCA.Bundle) throws -> [UInt8] {
        let certificate = try #require(try CertChain.certificates(fromPEM: bundle.caCertificatePEM).first)
        let der = SecCertificateCopyData(certificate) as Data
        return Array(SHA256.hash(data: der).prefix(16))
    }

    private func expectCertlessPairError(_ expected: CertlessPairError, _ operation: () throws -> Void) {
        do {
            try operation()
            Issue.record("Expected \(expected)")
        } catch let error as CertlessPairError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}
