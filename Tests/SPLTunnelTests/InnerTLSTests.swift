// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Network
import Security
import Testing
@testable import SPLTunnel

private struct InnerTLSTestTimeout: Error, Sendable {}
private let innerTLSClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")

@Suite(
    "InnerTLS",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct InnerTLSTests {
    @Test func stateErrorMappingClassifiesPeerAccessDeniedForFailedAndWaiting() {
        // Security/SecBase.h: errSSLPeerAccessDenied is -9832 on Apple platforms.
        for state in [NWConnection.State.failed(.tls(-9832)), .waiting(.tls(-9832))] {
            guard let error = preReadyNetworkError(from: state) else {
                Issue.record("Expected a pre-ready Network.framework error")
                continue
            }
            #expect(innerTLSError(for: error) == .peerAccessDenied)
        }

        for error in [NWError.tls(-9838), NWError.tls(-9800), NWError.posix(.ECONNREFUSED)] {
            guard case .handshakeFailed = innerTLSError(for: error) else {
                Issue.record("Expected generic handshake failure")
                continue
            }
        }
    }

    @Test func lanOneKiBPlaintextBytesRoundTripByteEqualAgainstInProcessTLSEcho() async throws {
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture)
        try await server.start()
        let port = await server.port

        let tls = try await InnerTLS.connectLAN(host: "127.0.0.1", port: port, pairing: fixture.pairing)
        let payload = Data((0..<1024).map { UInt8($0 % 251) })
        try await tls.send(payload)
        let echoed = try await firstInbound(from: tls.inbound)
        await tls.close()
        await server.stop()

        #expect(echoed == payload)
    }

    @Test func lanWrongCAInPinFailsHandshake() async throws {
        let fixture = try TestCA.make()
        let wrongServerFixture = try TestCA.make()
        let server = TLSEchoServer(bundle: wrongServerFixture, clientCAPEM: fixture.caCertificatePEM)
        try await server.start()
        let port = await server.port

        await expectInnerTLSError(.peerNotPinned) {
            _ = try await InnerTLS.connectLAN(host: "127.0.0.1", port: port, pairing: fixture.pairing)
        }
        await server.stop()
    }

    @Test func lanServerRejectingClientCertFailsHandshake() async throws {
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture, rejectClientCertificate: true)
        try await server.start()
        let port = await server.port

        await expectClientCertificateRejection {
            let tls = try await InnerTLS.connectLAN(host: "127.0.0.1", port: port, pairing: fixture.pairing)
            try await tls.send(Data([0x01]))
            guard try await firstInbound(from: tls.inbound) != nil else {
                throw InnerTLSError.handshakeFailed("server closed")
            }
            await tls.close()
        }
        #expect(await server.clientLeafFingerprint == (try TestCA.fingerprint(certificatePEM: fixture.clientCertificatePEM)))
        await server.stop()
    }

    @Test func lanServerFixtureCapturesClientLeafCertificate() async throws {
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture)
        try await server.start()
        let port = await server.port

        let tls = try await InnerTLS.connectLAN(host: "127.0.0.1", port: port, pairing: fixture.pairing)
        try await tls.send(Data([0x01]))
        _ = try await firstInbound(from: tls.inbound)
        let captured = await server.clientLeafFingerprint
        await tls.close()
        await server.stop()

        #expect(captured == (try TestCA.fingerprint(certificatePEM: fixture.clientCertificatePEM)))
    }

    @Test func relayOneKiBPlaintextBytesRoundTripViaWSToTLSBridgeByteEqual() async throws {
        // proto/session.md:71-73,113 the dial WebSocket becomes the inner TLS tunnel.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture)
        try await tlsServer.start()
        let tlsPort = await tlsServer.port
        let relay = RelayBridgeServer(tlsPort: tlsPort)
        try await relay.start()
        let relayPort = await relay.port

        let transport = try await DialClient.dialRelay(
            endpoint: RelayEndpoint.unchecked(try #require(URL(string: "ws://127.0.0.1:\(relayPort)"))),
            instanceID: fixture.pairing.instanceID,
            authToken: deviceToken(from: fixture.pairing),
            path: "session/dial",
            clientInfo: innerTLSClientInfo
        )
        let tls = try await InnerTLS.connectViaTransport(transport: transport, pairing: fixture.pairing)
        let payload = Data((0..<1024).map { UInt8(($0 * 7) % 251) })
        try await tls.send(payload)
        let echoed = try await firstInbound(from: tls.inbound)
        await tls.close()
        await relay.stop()
        await tlsServer.stop()

        #expect(echoed == payload)
    }

    @Test func pairingTLSConnectionReturnsAnchorSPKIAndRejectsMissingAnchor() async throws {
        // Pairing TLS must return the anchor SPKI and surface missing anchors as peerNotPinned.
        let fixture = try TestCA.make()
        let caCertificate = try #require(try CertChain.certificates(fromPEM: fixture.caCertificatePEM).first)
        let caSPKI = try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: caCertificate)
        let caPin = PairingCAPin(kind: .spkiSHA256, prefixBytes: Array(SHA256.hash(data: Data(caSPKI)).prefix(16)))

        let tlsServer = TLSEchoServer(bundle: fixture, requiresClientCertificate: false)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let relayPort = await relay.port

        let transport = try await DialClient.dialRelay(
            endpoint: RelayEndpoint.unchecked(try #require(URL(string: "ws://127.0.0.1:\(relayPort)"))),
            instanceID: "pair",
            authToken: "token",
            path: "session/dial",
            clientInfo: innerTLSClientInfo
        )
        let pairingConnection = try await InnerTLS.connectPairingViaTransport(transport: transport, caPin: caPin)
        #expect(pairingConnection.caSPKIDER == caSPKI)
        await pairingConnection.tls.close()

        let wrongFixture = try TestCA.make()
        let wrongCACertificate = try #require(try CertChain.certificates(fromPEM: wrongFixture.caCertificatePEM).first)
        let wrongSPKI = try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: wrongCACertificate)
        let wrongPin = PairingCAPin(kind: .spkiSHA256, prefixBytes: Array(SHA256.hash(data: Data(wrongSPKI)).prefix(16)))
        let rejectedTransport = try await DialClient.dialRelay(
            endpoint: RelayEndpoint.unchecked(try #require(URL(string: "ws://127.0.0.1:\(relayPort)"))),
            instanceID: "pair",
            authToken: "token",
            path: "session/dial",
            clientInfo: innerTLSClientInfo
        )
        await expectInnerTLSError(.peerNotPinned) {
            _ = try await InnerTLS.connectPairingViaTransport(transport: rejectedTransport, caPin: wrongPin)
        }
        await relay.stop()
        await tlsServer.stop()
    }

    private func firstInbound(from stream: AsyncThrowingStream<Data, Error>) async throws -> Data? {
        try await withThrowingTaskGroup(of: Data?.self) { group in
            group.addTask {
                for try await data in stream {
                    return data
                }
                return nil
            }
            group.addTask {
                try await Task.sleep(for: .seconds(3))
                throw InnerTLSTestTimeout()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    private func deviceToken(from pairing: StoredPairing) -> String {
        if case .enrolled(let deviceToken, _) = pairing.relayEnrollment {
            return deviceToken
        }
        return ""
    }

    private func expectInnerTLSError(
        _ expected: InnerTLSError,
        _ operation: @escaping @Sendable () async throws -> Void
    ) async {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await operation()
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(3))
                    throw InnerTLSTestTimeout()
                }
                try await group.next()!
                group.cancelAll()
            }
            Issue.record("Expected \(expected)")
        } catch let error as InnerTLSError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }

    private func expectClientCertificateRejection(
        _ operation: @escaping @Sendable () async throws -> Void
    ) async {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await operation()
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(3))
                    throw InnerTLSTestTimeout()
                }
                try await group.next()!
                group.cancelAll()
            }
            Issue.record("Expected client certificate rejection")
        } catch InnerTLSError.handshakeFailed(_) {
        } catch InnerTLSError.receiveFailed(_) {
        } catch {
            Issue.record("Expected handshakeFailed or receiveFailed, got \(error)")
        }
    }
}
