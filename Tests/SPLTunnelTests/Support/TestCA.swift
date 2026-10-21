// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Security
import Testing
@testable import SPLTunnel

enum TestCA {
    struct Bundle: Sendable {
        let caCertificatePEM: String
        let caPrivateKeyPEM: String
        let serverCertificatePEM: String
        let serverPrivateKeyPEM: String
        let clientCertificatePEM: String
        let clientPrivateKeyPEM: String
        let pairing: StoredPairing
    }

    static func make(localEndpoints: [LocalEndpoint] = []) throws -> Bundle {
        let caKey = P256.Signing.PrivateKey()
        let serverKey = P256.Signing.PrivateKey()
        let clientKey = P256.Signing.PrivateKey()

        let caDER = try certificate(
            subject: "solstone-test-ca",
            issuer: "solstone-test-ca",
            subjectPublicKey: caKey.publicKey,
            issuerPrivateKey: caKey,
            isCA: true,
            extendedKeyUsage: []
        )
        let serverDER = try certificate(
            subject: "localhost",
            issuer: "solstone-test-ca",
            subjectPublicKey: serverKey.publicKey,
            issuerPrivateKey: caKey,
            isCA: false,
            extendedKeyUsage: [CertBuilder.oidServerAuth],
            subjectAlternativeNames: true
        )
        let clientDER = try certificate(
            subject: "solstone-test-client",
            issuer: "solstone-test-ca",
            subjectPublicKey: clientKey.publicKey,
            issuerPrivateKey: caKey,
            isCA: false,
            extendedKeyUsage: [CertBuilder.oidClientAuth]
        )

        let caPEM = CryptoCSR.pemEncode(caDER, label: "CERTIFICATE")
        let caKeyPEM = CryptoCSR.pemEncode(CryptoCSR.exportPKCS8(caKey), label: "PRIVATE KEY")
        let serverPEM = CryptoCSR.pemEncode(serverDER, label: "CERTIFICATE")
        let clientPEM = CryptoCSR.pemEncode(clientDER, label: "CERTIFICATE")
        let clientKeyPEM = CryptoCSR.pemEncode(CryptoCSR.exportPKCS8(clientKey), label: "PRIVATE KEY")

        let pairing = StoredPairing(
            instanceID: "test-instance",
            homeLabel: "test home",
            relayEndpoint: "wss://127.0.0.1:1",
            fingerprint: "",
            clientCertPEM: clientPEM,
            clientKeyPEM: clientKeyPEM,
            caChainPEM: caPEM,
            relayEnrollment: .enrolled(deviceToken: "test-token", expiresAt: nil),
            localEndpoints: localEndpoints,
            pairedAt: Date(timeIntervalSince1970: 0)
        )

        return Bundle(
            caCertificatePEM: caPEM,
            caPrivateKeyPEM: caKeyPEM,
            serverCertificatePEM: serverPEM,
            serverPrivateKeyPEM: CryptoCSR.pemEncode(CryptoCSR.exportPKCS8(serverKey), label: "PRIVATE KEY"),
            clientCertificatePEM: clientPEM,
            clientPrivateKeyPEM: clientKeyPEM,
            pairing: pairing
        )
    }

    /// A server leaf signed by `issuer`'s CA, presented with `presentedCAPEM` (the issuer's own
    /// CA unless given) as the rest of its chain.
    static func serverIdentity(
        signedBy issuer: Bundle,
        presentedCAPEM: String? = nil,
        notBefore: Date = Date(timeIntervalSinceNow: -3600),
        notAfter: Date = Date(timeIntervalSinceNow: 86400)
    ) throws -> TLSServerIdentity {
        let caKey = try CryptoCSR.pkcs8PEMToPrivateKey(issuer.caPrivateKeyPEM)
        let serverKey = P256.Signing.PrivateKey()
        let leafDER = try CertBuilder.certificate(
            subject: "localhost",
            issuer: "solstone-test-ca",
            subjectPublicKey: serverKey.publicKey,
            issuerPrivateKey: caKey,
            isCA: false,
            extendedKeyUsage: [CertBuilder.oidServerAuth],
            subjectAlternativeNames: true,
            notBefore: notBefore,
            notAfter: notAfter
        )
        let leafPEM = CryptoCSR.pemEncode(leafDER, label: "CERTIFICATE")
        return TLSServerIdentity(
            chainPEM: "\(leafPEM)\n\(presentedCAPEM ?? issuer.caCertificatePEM)",
            privateKeyPEM: CryptoCSR.pemEncode(CryptoCSR.exportPKCS8(serverKey), label: "PRIVATE KEY")
        )
    }

    /// The journal ID of a fixture's CA, as a peer presenting it would claim.
    static func journalID(of bundle: Bundle) throws -> String {
        let ca = try #require(try CertChain.certificates(fromPEM: bundle.caCertificatePEM).first)
        return try CertChain.jidFromSPKI(CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: ca))
    }

    static func secIdentity(certificatePEM: String, privateKeyPEM: String) throws -> sec_identity_t {
        let pairing = StoredPairing(
            instanceID: "identity",
            homeLabel: "identity",
            relayEndpoint: "wss://127.0.0.1:1",
            fingerprint: "",
            clientCertPEM: certificatePEM,
            clientKeyPEM: privateKeyPEM,
            caChainPEM: certificatePEM,
            relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
            pairedAt: Date(timeIntervalSince1970: 0)
        )
        return try InnerTLS.makeIdentity(pairing: pairing)
    }

    static func fingerprint(certificatePEM: String) throws -> String {
        guard let certificate = try CertChain.certificates(fromPEM: certificatePEM).first else {
            throw CertChainError.emptyChain
        }
        return CertChain.sha256Fingerprint(of: certificate)
    }

    private static func certificate(
        subject: String,
        issuer: String,
        subjectPublicKey: P256.Signing.PublicKey,
        issuerPrivateKey: P256.Signing.PrivateKey,
        isCA: Bool,
        extendedKeyUsage: [[UInt64]],
        subjectAlternativeNames: Bool = false
    ) throws -> [UInt8] {
        try CertBuilder.certificate(
            subject: subject,
            issuer: issuer,
            subjectPublicKey: subjectPublicKey,
            issuerPrivateKey: issuerPrivateKey,
            isCA: isCA,
            extendedKeyUsage: extendedKeyUsage,
            subjectAlternativeNames: subjectAlternativeNames
        )
    }
}
