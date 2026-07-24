// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Network
import Security
import Testing
@testable import SPLTunnel

@Suite("InnerTLS certless")
struct InnerTLSCertlessTests {
    @Test func certlessTrustAcceptsMatchingCAAndRejectsWrongCA() throws {
        // proto/pairing.md:147-163 everyday tunnel TLS pins the returned CA chain.
        let chain = try CertChain.certificates(fromPEM: CertlessTrustFixtures.chainPEM)
        let wrongChain = try CertChain.certificates(fromPEM: CertlessTrustFixtures.wrongChainPEM)
        #expect(chain.count == 2)
        #expect(wrongChain.count == 2)
        #expect(Self.der(chain[0]) != Self.der(chain[1]))

        let caPin = Self.pin16(chain[1])
        let wrongCAPin = Self.pin16(wrongChain[1])

        #expect(InnerTLS.certlessTrustAccepts(chain: chain, caFingerprintBytes: caPin))
        #expect(!InnerTLS.certlessTrustAccepts(chain: chain, caFingerprintBytes: wrongCAPin))
        #expect(!InnerTLS.certlessTrustAccepts(chain: wrongChain, caFingerprintBytes: wrongCAPin))
        #expect(!InnerTLS.certlessTrustAccepts(chain: chain, caFingerprintBytes: Array(caPin.dropLast())))
    }

    @Test func pairingTrustChecksPinnedCertificateFromLiveChainAndEvaluatesThatChain() throws {
        // proto/pair-window.md:100 pins pairing to the inner TLS channel bound to ca_fp_spki from the link.
        let chain = try CertChain.certificates(fromPEM: CertlessTrustFixtures.chainPEM)
        let wrongChain = try CertChain.certificates(fromPEM: CertlessTrustFixtures.wrongChainPEM)
        let caPin = PairingCAPin(kind: .certificateSHA256, prefixBytes: Self.pin16(chain[1]))
        let wrongCAPin = PairingCAPin(kind: .certificateSHA256, prefixBytes: Self.pin16(wrongChain[1]))

        #expect(InnerTLS.pairingTrustAccepts(chain: chain, caPin: caPin))
        #expect(!InnerTLS.pairingTrustAccepts(chain: chain, caPin: wrongCAPin))
        #expect(!InnerTLS.pairingTrustAccepts(chain: wrongChain, caPin: wrongCAPin))
    }

    @Test func bridgeListenerParametersBindLoopback() throws {
        // Relay bridge factories must bind listener parameters to loopback only.
        try Self.expectLoopback(InnerTLS.makeBridgeListenerParameters())
        try Self.expectLoopback(InnerTLS.makeBridgeListenerParameters())
    }

    private static func expectLoopback(_ parameters: NWParameters) throws {
        let endpoint = try #require(parameters.requiredLocalEndpoint)
        guard case .hostPort(let host, let port) = endpoint else {
            Issue.record("expected hostPort endpoint")
            return
        }

        #expect(host == NWEndpoint.Host("127.0.0.1"))
        #expect(port == .any)
    }

    private static func pin16(_ certificate: SecCertificate) -> [UInt8] {
        Array(SHA256.hash(data: der(certificate)).prefix(16))
    }

    private static func der(_ certificate: SecCertificate) -> Data {
        SecCertificateCopyData(certificate) as Data
    }
}
